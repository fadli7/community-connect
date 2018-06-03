from facebook import db, Event
import random, string

for event in Event.query.all():
    event.attandance_code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    db.session.add(event)
    db.session.commit()