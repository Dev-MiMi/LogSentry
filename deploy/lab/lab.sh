#!/bin/bash
set -euo pipefail
services=(logsentry-web logsentry-proxy logsentry-collector logsentry-forwarder
          logsentry-wazuh-export wazuh-manager wazuh-indexer filebeat wazuh-dashboard)
case "${1:-status}" in
    start) sudo systemctl start logsentry-lab.target ;;
    stop) sudo systemctl stop logsentry-lab.target "${services[@]}" ;;
    restart)
        sudo systemctl stop logsentry-lab.target "${services[@]}"
        sudo systemctl start logsentry-lab.target
        ;;
    status)
        systemctl --no-pager --full status logsentry-lab.target \
            logsentry-web logsentry-proxy logsentry-collector logsentry-forwarder \
            logsentry-wazuh-export wazuh-manager wazuh-indexer filebeat wazuh-dashboard
        ;;
    *) echo "Usage: bash deploy/lab/lab.sh {start|stop|restart|status}"; exit 2 ;;
esac
