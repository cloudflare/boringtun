use std::pin::Pin;
use tokio::task::JoinHandle;

pub struct Task {
    name: &'static str,
    handle: Option<JoinHandle<()>>,
}

pub trait TaskOutput: Sized + Send + 'static {
    fn handle(self) {}
}

impl TaskOutput for () {}

impl<T, E> TaskOutput for Result<T, E>
where
    Self: Send + 'static,
    E: std::fmt::Debug,
{
    fn handle(self) {
        if let Err(e) = self {
            log::error!("task errored {e:?}");
        }
    }
}

impl Task {
    #[track_caller]
    pub fn spawn<Fut, O>(name: &'static str, fut: Fut) -> Self
    where
        Fut: Future<Output = O> + Send + 'static,
        O: TaskOutput,
    {
        let handle = tokio::spawn(async move {
            let output = fut.await;
            log::debug!("task {name:?} exited"); // TODO: trace?
            TaskOutput::handle(output);
        });

        Task {
            name,
            handle: Some(handle),
        }
    }
}

impl Future for Task {
    type Output = <JoinHandle<()> as Future>::Output;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.handle.as_mut().map(Pin::new).unwrap().poll(cx)
    }
}

impl Task {
    pub async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            match handle.await {
                Err(e) if e.is_panic() => {
                    log::error!("task {} panicked: {e:#?}", self.name);
                }
                _ => {
                    log::debug!("stopped task {}", self.name);
                }
            }
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            log::debug!("dropped task {}", self.name);
            handle.abort();
        }
    }
}
