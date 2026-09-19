
class KeyRing:

    def __init__(self):
        self.keys = []

    def add_key(self, key):

        if not self.contains(key["KeyID"]):
            self.keys.append(key)

    def remove_key(self, key_id):

        for key in self.keys:

            if key["KeyID"] == key_id:
                self.keys.remove(key)
                return True

        return False

    def get_key(self, key_id):

        for key in self.keys:
            if key["KeyID"] == key_id:
                return key

        return None

    def get_key_by_email(self, email):

        for key in self.keys:
            if key["Email"] == email:
                return key

        return None

    def get_all_keys(self):
        return self.keys

    def contains(self, key_id):

        for key in self.keys:
            if key["KeyID"] == key_id:
                return True

        return False
