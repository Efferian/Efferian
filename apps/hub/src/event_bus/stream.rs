use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use efferian_authz::AuthContext;
use efferian_protocol::{EventEnvelope, EventStreamFrame};
use hyper::body::{Body as HttpBody, Frame};
use tokio::sync::{broadcast, watch};
use tokio::time::{Instant, Interval, MissedTickBehavior, Sleep};

use super::{AuthorizedPage, CATCH_UP_LIMIT, EventKinds, EventReader, PageError};
use crate::storage::{EventsPageRaw, EventsReadError, RevocationWatch, StorageClock, StoredEvent};

const PING_INTERVAL: Duration = Duration::from_secs(15);

pub(super) fn body(
    reader: EventReader,
    shutdown: watch::Receiver<bool>,
    kinds: EventKinds,
    revocations: RevocationWatch,
    events: broadcast::Receiver<Arc<StoredEvent>>,
    after: i64,
    initial: AuthorizedPage,
) -> Body {
    let mut ping = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let AuthorizedPage {
        scope,
        events: page,
    } = initial;
    let expiry = scope
        .token
        .expires_at_ms
        .map(|deadline| expiry_sleep(reader.clock.as_ref(), deadline));
    let stream = EventStream {
        context: scope,
        kinds,
        revocations,
        shutdown,
        ping,
        expiry,
        clock: reader.clock.clone(),
        feed: Feed {
            reader,
            events,
            after,
            page: Some(Page::new(page.latest_seq, page)),
            pending: None,
        },
    };
    Body::new(NdjsonBody {
        next: Some(Box::pin(stream.next_frame())),
    })
}

type NextFrame = Pin<Box<dyn Future<Output = Option<(EventStream, EventStreamFrame)>> + Send>>;

struct NdjsonBody {
    next: Option<NextFrame>,
}

impl HttpBody for NdjsonBody {
    type Data = Bytes;
    type Error = serde_json::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let Some(next) = &mut this.next else {
            return Poll::Ready(None);
        };
        let frame = std::task::ready!(next.as_mut().poll(cx));
        this.next = None;
        let Some((stream, frame)) = frame else {
            return Poll::Ready(None);
        };
        let result = serde_json::to_vec(&frame).map(|mut bytes| {
            bytes.push(b'\n');
            Frame::data(Bytes::from(bytes))
        });
        if result.is_ok() && !matches!(frame, EventStreamFrame::ResyncRequired { .. }) {
            this.next = Some(Box::pin(stream.next_frame()));
        }
        Poll::Ready(Some(result))
    }

    fn is_end_stream(&self) -> bool {
        self.next.is_none()
    }
}

struct EventStream {
    context: AuthContext,
    kinds: EventKinds,
    revocations: RevocationWatch,
    shutdown: watch::Receiver<bool>,
    clock: Arc<dyn StorageClock>,
    ping: Interval,
    expiry: Option<Pin<Box<Sleep>>>,
    feed: Feed,
}

impl EventStream {
    async fn next_frame(mut self) -> Option<(Self, EventStreamFrame)> {
        let frame = loop {
            tokio::select! {
                biased;
                _ = self.shutdown.wait_for(|stopped| *stopped) => return None,
                signal = self.revocations.recv() => {
                    if signal.map_or(true, |signal| signal.affects_caller(&self.context)) {
                        return None;
                    }
                }
                _ = poll_expiry(&mut self.expiry) => {
                    let deadline = self.context.token.expires_at_ms?;
                    if !self.context.token.is_active(self.clock.wall_now_ms()) {
                        return None;
                    }
                    self.expiry = Some(expiry_sleep(self.clock.as_ref(), deadline));
                }
                _ = self.ping.tick() => break EventStreamFrame::Ping {},
                item = self.feed.next(&self.context, &self.kinds) => match item {
                    Ok(FeedItem::Event(event)) => break EventStreamFrame::Event { event },
                    Ok(FeedItem::Skipped) => {}
                    Err(PageError::Events(EventsReadError::ResyncRequired {
                        oldest_available_seq,
                        latest_seq,
                    })) => {
                        break EventStreamFrame::ResyncRequired { oldest_available_seq, latest_seq };
                    }
                    Ok(FeedItem::Closed) | Err(_) => return None,
                }
            }
            tokio::task::consume_budget().await;
        };
        if !self.can_send_frame() {
            return None;
        }
        Some((self, frame))
    }

    fn can_send_frame(&mut self) -> bool {
        use broadcast::error::TryRecvError;

        if *self.shutdown.borrow() || !self.context.token.is_active(self.clock.wall_now_ms()) {
            return false;
        }
        loop {
            match self.revocations.try_recv() {
                Ok(signal) if signal.affects_caller(&self.context) => return false,
                Ok(_) => {}
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Lagged(_) | TryRecvError::Closed) => return false,
            }
        }
    }
}

fn expiry_sleep(clock: &dyn StorageClock, deadline: i64) -> Pin<Box<Sleep>> {
    let remaining = u64::try_from(deadline.saturating_sub(clock.wall_now_ms())).unwrap_or(0);
    Box::pin(tokio::time::sleep(Duration::from_millis(remaining)))
}

async fn poll_expiry(sleep: &mut Option<Pin<Box<Sleep>>>) {
    match sleep.as_mut() {
        Some(timer) => timer.as_mut().await,
        None => pending().await,
    }
}

type PageRead = Pin<Box<dyn Future<Output = Result<EventsPageRaw, PageError>> + Send>>;

struct Feed {
    reader: EventReader,
    events: broadcast::Receiver<Arc<StoredEvent>>,
    after: i64,
    page: Option<Page>,
    pending: Option<(Option<i64>, PageRead)>,
}

struct Page {
    through: i64,
    scanned_through: i64,
    has_more: bool,
    items: std::vec::IntoIter<StoredEvent>,
}

impl Page {
    fn new(through: i64, page: EventsPageRaw) -> Self {
        Self {
            through,
            scanned_through: page.scanned_through,
            has_more: page.has_more,
            items: page.items.into_iter(),
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "Move the event into its frame without allocating."
)]
enum FeedItem {
    Event(EventEnvelope),
    Skipped,
    Closed,
}

impl Feed {
    async fn next(&mut self, ctx: &AuthContext, kinds: &EventKinds) -> Result<FeedItem, PageError> {
        loop {
            if let Some((through, pending)) = &mut self.pending {
                let page = pending.await?;
                self.page = Some(Page::new(through.unwrap_or(page.latest_seq), page));
                self.pending = None;
            }
            if let Some(page) = &mut self.page {
                if let Some(event) = page.items.next() {
                    return Ok(self.observe(&event, ctx, kinds));
                }
                let more = page.has_more.then_some(page.through);
                self.after = page.scanned_through;
                self.page = None;
                if let Some(through) = more {
                    self.read_page(Some(through), kinds);
                    continue;
                }
            }

            match self.events.recv().await {
                Ok(event) => return Ok(self.observe(&event, ctx, kinds)),
                Err(broadcast::error::RecvError::Lagged(_)) => self.read_page(None, kinds),
                Err(broadcast::error::RecvError::Closed) => return Ok(FeedItem::Closed),
            }
        }
    }

    fn read_page(&mut self, through: Option<i64>, kinds: &EventKinds) {
        // Preserve this read across selections of a ping or irrelevant revocation.
        let after = self.after;
        let reader = self.reader.clone();
        let kinds = kinds.clone();
        self.pending = Some((
            through,
            Box::pin(async move {
                reader
                    .read(after, through, CATCH_UP_LIMIT, false, &kinds)
                    .await
                    .map(|page| page.events)
            }),
        ));
    }

    fn observe(&mut self, event: &StoredEvent, ctx: &AuthContext, kinds: &EventKinds) -> FeedItem {
        if event.envelope.seq <= self.after {
            return FeedItem::Skipped;
        }
        self.after = event.envelope.seq;
        // SQLite pages already passed their fresh snapshot's authorization.
        // The opening scope also applies here so a grant cannot widen the stream.
        if kinds.permits(ctx, event) {
            FeedItem::Event(event.envelope.clone())
        } else {
            FeedItem::Skipped
        }
    }
}
