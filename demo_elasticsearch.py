from elasticsearch import Elasticsearch
es = Elasticsearch([{"host": "localhost", "port": 9200}])

body = {"query": {
        "match_all": {
    }}

search_obj = es.search(index="instagram-following",body=body)
print(search_obj["hits"]["hits"])
# for i in ids:
#     search_obj = es.delete(index="instagram-photoposted",id="GwkugG0B1AH7gCYmVn-W")
# search_obj = es.delete(index="instagram-following",id="HAkugG0B1AH7gCYmd3-L")