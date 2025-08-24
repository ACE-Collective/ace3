#!/usr/bin/env sh
if [ ! -f /data/.init_done ]; then
    mc alias set local http://minio:9000 ace3 "$(cat /auth/passwords/minio)" || true
    mc admin user add local ace3api "$(cat /auth/passwords/minio)" || true
    mc admin user add local ace3apitest 5ad82077-e6bf-471d-8f44-979c4f541082 || true
    mc mb local/ace3 || true
    mc mb local/ace3test || true
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
    touch /data/.init_done
else
    echo "MinIO already initialized -- skipping initialization"
fi
