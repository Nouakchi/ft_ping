# Step 1: Choose a base image.
# debian:bookworm-slim is Debian 12, a modern version that is "> 7.0".
# The "slim" variant is smaller, making builds and downloads faster.
FROM debian:bookworm-slim

# Step 2: Install necessary build tools and libraries.
# - 'build-essential' bundles everything needed to compile C/C++ (gcc, make, etc.).
# - 'iputils-ping' is installed so you can test network connectivity inside the container
#   with the real 'ping' command as a reference.
RUN apt-get update && apt-get install -y \
    build-essential \
    iputils-ping \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Step 3: Set the working directory for your project inside the container.
WORKDIR /app

# Step 4: Copy all your project files (source, Makefile, includes) from your
# current directory on your host machine into the container's /app directory.
COPY . .

# Step 5: Compile your program.
# This runs your Makefile to build the 'ft_ping' executable.
# We run 'make clean' first to ensure a fresh build.
# RUN make clean && make

# Step 6: Define the default command to run when the container starts.
# This is useful for testing, but we will override it for development.
CMD ["/bin/bash"]