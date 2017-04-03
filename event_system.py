

class Event:
    """
    Simple Event class which caries information about event. It is used for notifications.
    This class is ABSTRACT.
    """
    def __init__(self, event):
        self.event = event

    def get_event(self):
        return self.event


class EventListener:
    """
    Class defines notify operation for Event Subscribers.
    This class is ABSTRACT.
    """
    def notify(self, event: Event):
        raise NotImplementedError("Should have implemented this")

    def __str__(self):
        raise NotImplementedError("Should have implemented this")


class EventProducer:
    """
    Class allows to store event listeners and send them events.
    This class is ABSTRACT.
    """
    def __init__(self):
        self.listeners = {}
        self.events = []

    def add_event_support(self, event: Event):
        self.events.append(event)
        self.listeners.update({event: []})

    def subscribe_event(self, event: Event, listener: EventListener):
        if event not in self.listeners:
            raise Exception("Event '{}' not supported. Supported events are: ''".format(event, "".join(self.events)))
        self.listeners[event].append(listener)

    def notify_listeners(self, event: Event):
        for listener in self.listeners[event.__class__]:
            listener.notify(event)
