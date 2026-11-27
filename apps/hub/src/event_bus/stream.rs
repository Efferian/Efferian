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
use tokio::time::{Instant, Interval, MissedTickBehavior};

use super::{CATCH_UP_LIMIT, EventKinds};
use crate::http::AppState;
use crate::storage::{
    EventsPageRaw, EventsReadError, RevocationWatch, StorageClock, StorageHandle, StoredEvent,
};

const PING_INTERVAL: Duration = Duration::from_secs(15);

pub(super) fn body(
    state: AppState,
    context: AuthContext,
    kinds: EventKinds,
    revocations: RevocationWatch,
    events: broadcast::Receiver<Arc<StoredEvent>>,
    after: i64,
    initial: EventsPageRaw,
) -> Body {
    let shutdown = state.execution.shutdown_receiver();
    let mut ping = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let stream = EventStream {
        context,
        kinds,
        revocations,
        shutdown,
        ping,
        clock: state.clock,
        feed: Feed {
            storage: state.storage,
            events,
            after,
            page: Some(Page::new(initial.latest_seq, initial)),
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
    feed: Feed,
}

impl EventStream {
    async fn next_frame(mut self) -> Option<(Self, EventStreamFrame)> {
        let frame = {
            let expired = wait_for_expiry(self.clock.as_ref(), self.context.token.expires_at_ms);
            tokio::pin!(expired);
            loop {
                tokio::select! {
                    biased;
                    _ = self.shutdown.wait_for(|stopped| *stopped) => return None,
                    signal = self.revocations.recv() => {
                        if signal.map_or(true, |signal| signal.affects_caller(&self.context)) {
                            return None;
                        }
                    }
                    _ = &mut expired => return None,
                    _ = self.ping.tick() => break EventStreamFrame::Ping {},
                    item = self.feed.next(&self.context, &self.kinds) => match item {
                        Ok(FeedItem::Event(event)) => break EventStreamFrame::Event { event },
                        Ok(FeedItem::Skipped) => {}
                        Err(EventsReadError::ResyncRequired { oldest_available_seq, latest_seq }) => {
                            break EventStreamFrame::ResyncRequired { oldest_available_seq, latest_seq };
                        }
                        Ok(FeedItem::Closed) | Err(_) => return None,
                    }
                }
                tokio::task::consume_budget().await;
            }
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

async fn wait_for_expiry(clock: &dyn StorageClock, expiry: Option<i64>) {
    let Some(expiry) = expiry else {
        return pending().await;
    };
    while let Ok(remaining) = u64::try_from(expiry.saturating_sub(clock.wall_now_ms()))
        && remaining > 0
    {
        tokio::time::sleep(Duration::from_millis(remaining)).await;
    }
}

type PageRead = Pin<Box<dyn Future<Output = Result<EventsPageRaw, EventsReadError>> + Send>>;

struct Feed {
    storage: StorageHandle,
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
    async fn next(
        &mut self,
        ctx: &AuthContext,
        kinds: &EventKinds,
    ) -> Result<FeedItem, EventsReadError> {
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
                    self.read_page(Some(through));
                    continue;
                }
            }

            match self.events.recv().await {
                Ok(event) => return Ok(self.observe(&event, ctx, kinds)),
                Err(broadcast::error::RecvError::Lagged(_)) => self.read_page(None),
                Err(broadcast::error::RecvError::Closed) => return Ok(FeedItem::Closed),
            }
        }
    }

    fn read_page(&mut self, through: Option<i64>) {
        // Preserve this read across selections of a ping or irrelevant revocation.
        let after = self.after;
        let storage = self.storage.clone();
        let hub = *storage.hub_id();
        self.pending = Some((
            through,
            Box::pin(async move {
                storage
                    .read_snapshot(move |conn| {
                        StorageHandle::read_events_page(
                            conn,
                            hub,
                            after,
                            through,
                            CATCH_UP_LIMIT,
                            false,
                        )
                    })
                    .await
            }),
        ));
    }

    fn observe(&mut self, event: &StoredEvent, ctx: &AuthContext, kinds: &EventKinds) -> FeedItem {
        if event.envelope.seq <= self.after {
            return FeedItem::Skipped;
        }
        self.after = event.envelope.seq;
        if kinds.permits(ctx, event) {
            FeedItem::Event(event.envelope.clone())
        } else {
            FeedItem::Skipped
        }
    }
}
