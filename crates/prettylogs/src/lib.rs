#[cfg(debug_assertions)]
pub fn init_logging() {
    tracing_subscriber::FmtSubscriber::builder()
        .pretty()
        .with_line_number(true)
        .with_file(true)
        .without_time()
        .init();
}
#[cfg(not(debug_assertions))]
pub fn init_logging() {
    use tracing_subscriber::EnvFilter;
    //create env that prevents logs coming from anywhere but the local crates of this project
    // Set all dependencies to "warn" level
    let deps_filter = EnvFilter::default().add_directive("warn".parse().unwrap());

    // Add local crates individually at "info" level
    let local_filter = EnvFilter::default()
        .add_directive("appstate=info".parse().unwrap())
        .add_directive("config=info".parse().unwrap())
        .add_directive("database=info".parse().unwrap())
        .add_directive("filehelpers=info".parse().unwrap())
        .add_directive("macros=info".parse().unwrap())
        .add_directive("prettylogs=info".parse().unwrap())
        .add_directive("streamdeckreplacement=info".parse().unwrap())
        .add_directive("webserver=info".parse().unwrap());
    tracing_subscriber::FmtSubscriber::builder()
        .pretty()
        .without_time()
        .with_line_number(true)
        .with_file(true)
        .with_env_filter(deps_filter)
        .with_env_filter(local_filter)
        .init();
}
