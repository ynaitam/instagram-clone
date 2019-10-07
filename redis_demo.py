import redis

r = redis.Redis('localhost')
list_of_dict
for key,val in list_of_dict:
    r.hset("pythonDict", key, val)