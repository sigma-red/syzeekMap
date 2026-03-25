#!/bin/bash
# syzeekMap Air-Gapped Deployment Script
#
# USAGE:
#   On the internet-connected build machine:
#     ./deploy-airgap.sh build      # Build image and export to .tar.gz
#
#   Transfer syzeekmap-image.tar.gz to the air-gapped SO manager, then:
#     ./deploy-airgap.sh load       # Load image from .tar.gz
#     ./deploy-airgap.sh run        # Start the container

set -e

IMAGE_NAME="syzeekmap:latest"
ARCHIVE="syzeekmap-image.tar.gz"

case "${1}" in
    build)
        echo "[*] Building Docker image..."
        docker build -t "$IMAGE_NAME" .
        echo "[*] Exporting image to $ARCHIVE..."
        docker save "$IMAGE_NAME" | gzip > "$ARCHIVE"
        SIZE=$(du -h "$ARCHIVE" | cut -f1)
        echo "[+] Done. Transfer $ARCHIVE ($SIZE) to your air-gapped SO manager."
        ;;
    load)
        if [ ! -f "$ARCHIVE" ]; then
            echo "[-] $ARCHIVE not found. Copy it to this directory first."
            exit 1
        fi
        echo "[*] Loading Docker image from $ARCHIVE..."
        docker load < "$ARCHIVE"
        echo "[+] Image loaded. Run './deploy-airgap.sh run' to start."
        ;;
    run)
        echo "[*] Starting syzeekMap..."
        if [ ! -f .env ]; then
            echo "[-] .env file not found. Copy .env.example to .env and configure it first."
            exit 1
        fi
        # Use docker run directly (no docker-compose needed on air-gapped host)
        docker run -d \
            --name syzeekmap \
            --restart unless-stopped \
            --network host \
            --env-file .env \
            "$IMAGE_NAME"
        echo "[+] syzeekMap running. Access at http://$(hostname -I | awk '{print $1}'):8080"
        ;;
    stop)
        echo "[*] Stopping syzeekMap..."
        docker stop syzeekmap && docker rm syzeekmap
        echo "[+] Stopped."
        ;;
    *)
        echo "Usage: $0 {build|load|run|stop}"
        echo ""
        echo "  build  - Build image and export to $ARCHIVE (internet-connected machine)"
        echo "  load   - Load image from $ARCHIVE (air-gapped machine)"
        echo "  run    - Start the container (air-gapped machine)"
        echo "  stop   - Stop and remove the container"
        exit 1
        ;;
esac
