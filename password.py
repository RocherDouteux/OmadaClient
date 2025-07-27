import hashlib
import base64

# Use in case of emergency
def shiro_hash(p, algorithm='sha256', iterations=500000, salt=b''):
    pw = p.encode('utf-8')
    digest = hashlib.new(algorithm)
    digest.update(pw + salt)
    result = digest.digest()
    for _ in range(iterations - 1):
        digest = hashlib.new(algorithm)
        digest.update(result)
        result = digest.digest()
    return base64.b64encode(result).decode()

password = "<HERE>"
hashed = shiro_hash(password)
shiro_format_hash = f"$shiro1$SHA-256$500000$${hashed}"

print(shiro_format_hash)


# db.iam_user.updateOne(
#   { _id: ObjectId("68861889878c1a1846e05562") },
#   { $set: { password: "<HERE>" } }
# )