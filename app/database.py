from app import db

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String, nullable=False)
    key_type = db.Column(db.String(10), nullable=False)
    key_value = db.Column(db.String, nullable=False)  

    def get_value(self):
        return self.key_value
    
    def get_response(self):
        return {"key_id": self.key_id, "key_value": self.key_value}


def store_key(key_type, key_id, key_value):
    
    new_key = Key(
        key_id=key_id,
        key_type=key_type,
        key_value=key_value
    )
    db.session.add(new_key)
    db.session.commit()

    return new_key


def get_key(key_type, key_id):

    key = Key.query.filter_by(key_id=key_id, key_type=key_type).first()
    if not key:
        return None
    return key.get_value()