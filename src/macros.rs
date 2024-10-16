#[macro_export]
macro_rules! spawn_tasks {
    ($state:expr, $($task:expr),*) => {
        {
            let handles: Vec<_> = vec![
                $(
                    spawn($task($state.clone())),
                )*
            ];

            handles
        }
    };
}
