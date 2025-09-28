#!/usr/bin/env sh
if [ ! -f /data/.init_done ]; then
    mc alias set local http://minio:9000 ace3 "$(cat /auth/passwords/minio)" || true
    mc admin user add local ace3api "$(cat /auth/passwords/minio)" || true
    mc admin user add local ace3apitest 5ad82077-e6bf-471d-8f44-979c4f541082 || true
    mc mb local/ace3 || true
    mc mb local/ace3test || true
    mc mb local/journal-emails || true
    # the ace3test user is used in integration tests so it only gets access to the ace3test bucket
    mc admin policy attach local readwrite --user ace3api || true
    cat > /tmp/ace3test-readwrite-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": [
        "arn:aws:s3:::ace3test",
        "arn:aws:s3:::ace3test/*"
      ]
    }
  ]
}
JSON
    mc admin policy create local ace3test-readwrite /tmp/ace3test-readwrite-policy.json || true
    mc admin policy attach local ace3test-readwrite --user ace3apitest || true
    rm /tmp/ace3test-readwrite-policy.json || true
    mc ilm rule add local/ace3 --expire-days 3 || true
    mc ilm rule add local/ace3test --expire-days 3 || true
    mc ilm rule add local/journal-emails --expire-days 30 || true
    # configure bucket notifications for email journal collector
    mc admin config set local \
      notify_amqp:local \
      url="amqp://ace3:$(cat /auth/passwords/rabbitmq)@${RABBITMQ_HOSTNAME:-rabbitmq}:5672" \
      exchange="minio-events" \
      exchange_type="topic" \
      routing_key="minio.object.*" \
      durable="on" \
      delivery_mode="2" \
      queue_dir="/opt/minio/events" \
      queue_limit="800000" || true
    # NOTE adding --json bypasses the requirement for a valid tty
    mc admin service restart local --json
    # wait for the service to restart
    for x in {1..10}; do
        echo "waiting for minio service to restart ($x/10)"
        if mc ls local --json > /dev/null 2>&1; then
            echo "service restarted successfully"
            break
        fi
        sleep 1
    done
    # the arn seems to always be the same so we'll hardcode it
    # this container doesn't have any tooling to extract it easily
    #mc admin info local --json
    SQS_ARN="arn:minio:sqs::local:amqp"
    mc event add local/journal-emails $SQS_ARN --event put || true
    mc event ls local/journal-emails $SQS_ARN
    touch /data/.init_done
else
    echo "MinIO already initialized -- skipping initialization"
fi
