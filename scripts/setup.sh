#!/bin/bash
# eBPF HTTP Monitor Setup Script

set -e

echo "Setting up eBPF HTTP Monitor environment..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS and install dependencies
if [ -f /etc/debian_version ]; then
    echo "Detected Debian/Ubuntu system"
    apt-get update
    apt-get install -y clang llvm linux-headers-$(uname -r) libbpf-dev
elif [ -f /etc/redhat-release ]; then
    echo "Detected RedHat/CentOS system"
    yum install -y clang llvm kernel-devel libbpf-devel
elif [ -f /etc/arch-release ]; then
    echo "Detected Arch Linux system"
    pacman -S --needed clang llvm linux-headers libbpf
else
    echo "Unsupported OS. Please install dependencies manually:"
    echo "- clang"
    echo "- llvm"
    echo "- linux-headers"
    echo "- libbpf-dev"
    exit 1
fi

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$MAJOR" -lt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 18 ]); then
    echo "Warning: Kernel version $KERNEL_VERSION is too old. Requires >= 4.18"
    echo "Some features may not work properly."
fi

echo "Environment setup completed successfully!"
echo "You can now run 'make build' to compile the program."