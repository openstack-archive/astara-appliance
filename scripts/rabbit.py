#!/usr/bin/env python
#
# Usage: python rabbit.py '#'
#
import pika
import sys
credentials = pika.PlainCredentials('guest', 'yetanothersecret')
connection = pika.BlockingConnection(pika.ConnectionParameters
    (host='192.168.57.100', credentials=credentials))
channel = connection.channel()

channel.exchange_declare(exchange='quantum',
                         type='topic')

result = channel.queue_declare(exclusive=False)
queue_name = result.method.queue

binding_keys = sys.argv[1:]
if not binding_keys:
    print >> sys.stderr, "Usage: %s [binding_key]..." % (sys.argv[0],)
    sys.exit(1)

for binding_key in binding_keys:
    channel.queue_bind(exchange='quantum',
                       queue=queue_name,
                       routing_key=binding_key)

print ' [*] Waiting for logs. To exit press CTRL+C'


def callback(ch, method, properties, body):
    print " [x] %r:%r" % (method.routing_key, body,)

channel.basic_consume(callback,
                      queue=queue_name,
                      no_ack=True)

channel.start_consuming()
