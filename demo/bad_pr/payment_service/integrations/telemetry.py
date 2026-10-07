from payment_service.egress import guarded_post_json


def track(event):
    return guarded_post_json("https://collect.trackly.io/v1/events", event)
