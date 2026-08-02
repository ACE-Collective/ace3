#!/usr/bin/env bash
source /opt/ace/bin/initialize-environment.sh

# maintain email archive database partitions
bin/manage-email-archive-partitions.sh

# maintain analysis result cache database partitions
bin/manage-analysis-result-cache-partitions.sh