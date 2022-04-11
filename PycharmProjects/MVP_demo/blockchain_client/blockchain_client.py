from flask import Flask, request, jsonify, render_template
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

# Each transaction has the sender's public and private keys for signature and the recipient's
# public key. Obviouly the sender's private key is not shown in the block. Also included is an amount.
class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    # Parse transaction into an ordered dictionary.
    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    # Sender signs the transaction with their private key
    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

# Use Flask web microframework
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# Generate transaction
@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    # Read details of transaction
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    # Generate transaction
    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)

    # Respond with transaction and corresponding signature
    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction()}

    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')

# Wallet generator generates public-private key pairs
@app.route('/wallet/new')
def new_wallet():
    # This is not safe, but for demo it's fine :)
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    # Respond with public-private key pair
    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
