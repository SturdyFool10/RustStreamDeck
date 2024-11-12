# Deckify

---

**Transform Your Phone into a PC Controller – Just Like a Stream Deck**

## Our Mission
---
Deckify’s mission is simple: to give everyone a secure, open-source way to turn their phone into a powerful PC control panel. With this app, you’ll have the flexibility to customize your setup and control your computer using just your mobile device.

## Important Usage & Documentation
---
Heads up: Deckify is designed for controlling **your own computer**. If you’ve been led here by someone else, install this software only if you’re setting it up for yourself. Don’t give access to anyone you wouldn’t want to have complete control over your system.

Once you’re set up, Deckify will create a `config.json` file, which houses all settings. Your login info is stored safely in an encrypted database within the local `auth` folder—keeping your credentials secure.

### Interface Configuration
---
In `config.json`, you’ll find an **interface option** that sets where Deckify can accept connections. By default, it’s open to all (`0.0.0.0`), meaning anyone who can reach the webserver can connect. Here’s how to change that, along with additional “magic” options you can try:

- **<your gateway’s IP>**: Limits access to devices within your internal network, protecting it even if the webserver is theoretically visible from the internet.

- **127.0.0.1**: Restricts connections to the device Deckify is running on, blocking all other devices—even those on the same network.

- **192.168.x.x (Local Network Subnet)**: Replace `x.x` with the specific local network range your router uses (like `192.168.0.0` or `192.168.1.0`). This option limits access to devices within a specific subnet on your local network, giving access to local devices while keeping it restricted to your home or office network.

- **Specific Device IPs**: Enter individual IP addresses for devices you want to connect (e.g., `192.168.1.5`). Only devices with the exact IPs you specify will be able to connect, allowing precise access control.

- **VPN IPs**: If you connect to your computer remotely over a VPN, set the interface to the IP range used by your VPN server. This allows only authenticated VPN connections, providing secure remote access.

- **Private IP Ranges (e.g., `10.x.x.x`)**: Use this if your setup includes multiple private subnets. The `10.x.x.x` range is often used in larger or complex private networks, so you can customize Deckify to allow only specific private IP ranges.

Each of these options offers a different level of accessibility and security based on your specific network setup and needs. Choose the one that best fits how you want to control your Deckify access!

### Port Configuration



Setting up the right port is a key step to keep your Deckify experience secure. By default, it’s set to port 80, but you can pick any port up to 65535. It’s a good idea to check online, like by searching “what services use port X” (where X is your chosen port number), to make sure it’s not typically used by other applications. This isn’t essential, but it can add a layer of security. While “security through obscurity” isn’t the best approach on its own, it can be part of a larger security plan to help protect you.



### Using Deckify



Deckify is a standalone package that runs smoothly on its default settings (which it will create if there’s no local `config.json` file). To get started, build the binary from source and launch it on your OS.



#### Building from Source



##### Windows



1. **Download Git for Windows.**

2. **Install Rust**  

   Visit [rustup.rs](https://rustup.rs/) to install Rust, making sure to select the right toolchain for your OS.

3. **Choose an Install Location**  

   Pick an empty location on a drive with at least 2GB of free space.

4. **Clone the Repository**  

   Open a terminal and run:

```bash

   git clone --recursive https://github.com/SturdyFool10/RustStreamDeck.git
```

5. **Navigate to the New Folder**

6. **Build Deckify**  

   Open a terminal in this folder and run:

```bash

   cargo build --release # "--release" makes the app faster and more efficient.

```

7. **Locate the Executable**  

   Find the `.exe` file in `/target/release`—that’s Deckify! You can move it anywhere, and it’ll run independently.



##### Linux



1. **Install Git**  

   Download or install Git for your Linux distribution.

2. **Install Rust**  

   Visit [rustup.rs](https://rustup.rs/) to install Rust, choosing the appropriate toolchain for your system.

3. **Choose an Install Location**  

   Pick a directory with at least 2GB of free space.

4. **Clone the Repository**  

   In a terminal, run:

```bash

   git clone --recursive https://github.com/SturdyFool10/RustStreamDeck.git

```

5. **Navigate to the New Folder**

6. **Build Deckify**  

   Open a terminal in this folder and run:

```bash

   cargo build --release # "--release" optimizes performance.
```

7. **Locate the Executable**  

   Find the executable file in `/target/release`.

8. **Create a Start Script (Optional)**  

   Move the executable to your desired location, then create a `start.sh` script with this content:

```bash

   #!/bin/bash



   # Deckify needs sudo permissions on Linux to run

   sudo ./StreamDeckReplacement

```

9. **Make the Script Executable**  

   Run the following command to make `start.sh` executable:

```bash

   chmod +x start.sh

```

10. **Run Deckify**  

    To start Deckify, run `./start.sh`, which provides the necessary elevated permissions for running a web server on Linux.



##### MacOS



1. **Install Git**  

   If you don’t already have Git, install it using [Homebrew](https://brew.sh/) or by downloading it directly from [Git-SCM](https://git-scm.com/).

```bash

   brew install git

```



2. **Install Rust**  

   Visit [rustup.rs](https://rustup.rs/) and follow the installation instructions. Ensure you install the appropriate toolchain for your macOS version.



3. **Choose an Install Location**  

   Navigate to a directory with at least 2GB of free space.



4. **Clone the Repository**  

   In your terminal, clone the Deckify repository:

```bash

   git clone --recursive https://github.com/SturdyFool10/RustStreamDeck.git

```

   Navigate into the newly created directory:

```bash

   cd RustStreamDeck

```



5. **Build Deckify**  

   Run the following command to build Deckify in release mode for optimized performance:

```bash

   cargo build --release # "--release" optimizes performance

```



6. **Locate the Executable**  

   Once the build is complete, find the Deckify executable in the `/target/release` directory.



7. **Run Deckify**  

   To start Deckify, open a terminal in the directory where the executable is located. If you're using a port above 1024, simply run:

```bash

   ./StreamDeckReplacement

```

   However, if you’re running Deckify on a port below 1024 (e.g., the default port 80), you’ll need to start it with elevated permissions. For that, use `sudo`:

```bash

   sudo ./StreamDeckReplacement

```



8. **(Optional) Create a Start Script**  

   You can create a `start.sh` script to simplify the startup process. Here’s an example:

```bash

   #!/bin/bash



   # Use elevated permissions only if needed (for ports < 1024)

   sudo ./StreamDeckReplacement

```



9. **Make the Script Executable**  

   After creating `start.sh`, make it executable:

```bash

   chmod +x start.sh

```



Now, you can start Deckify by running `./start.sh` in your terminal.



---



Deckify is now set up and ready to use on your OS of choice! You can move the executable and script to any preferred location, making it easy to launch whenever you need it.
