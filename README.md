# redis-bigkey-detector

redis-bigkey-detector 是一个无侵入、轻量级的Redis 大key 发现工具，它基于eBPF和uprobe实现。

## 使用方法

```
./redis-bigkey ${redis-pid} 
```

详细介绍：
