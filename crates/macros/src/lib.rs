#[macro_export]
macro_rules! spawn_tasks {
    ($state:expr, $($task:expr),*) => {
        {
            // Create a fixed-size array of JoinHandle tasks
            vec![
                $(
                    tokio::spawn($task($state.clone())),
                )*
            ]
        }
    };
}

#[macro_export]
macro_rules! await_any {
    ($func:expr, $( $task:expr ),* ) => {
        tokio::select! {
            //add a branch for every task
            $(
                _ = $task => {$func()}
            )*
        }.await;
    };
}
