pub fn init_logging() {
    tracing_subscriber::FmtSubscriber::builder()
        .pretty()
        .with_line_number(true)
        .with_file(true)
        .without_time()
        .init();
}
