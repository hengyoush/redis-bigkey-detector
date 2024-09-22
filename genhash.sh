
#!/bin/bash

# Redis 连接信息
REDIS_HOST="localhost"
REDIS_PORT="6379"
REDIS_KEY="myhash2"

# 使用 redis-cli 批量设置 10000 个字段到 hash key 中
for i in $(seq 1 100); do
    FIELD="field$i"
    VALUE="value$i"

    # 使用 HSET 命令设置单个字段
    redis-cli -h $REDIS_HOST -p $REDIS_PORT HSET $REDIS_KEY $FIELD $VALUE
done

echo "Successfully added 10000 fields to the hash $REDIS_KEY"

