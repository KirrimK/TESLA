from hashlib import blake2b, blake2s, sha256
import hmac
from time import perf_counter, time, sleep
from math import ceil, floor

class Sender:
    def __init__(self, initial_time, key_chain, T_int, intervals):
        self.T0 = initial_time
        self.key_chain = key_chain
        self.T_int = T_int
        self.intervals = intervals
        # self.d = disclosure_delay

# def create_key_chain(private_seed, N, interval):
def create_key_chain(private_seed, N):
    key_chain = []

    for i in range(0,N):
        if i == 0:
            h = sha256()
            h.update(private_seed)
            hash = h.hexdigest()
            key_chain.append(hash)
        else:
            h = sha256()
            h.update(key_chain[i-1].encode())
            hash = h.hexdigest()
            key_chain.append(hash)

    return key_chain

def sender_setup(private_seed, key_chain_length):
    n = 3 # Send a packet very n millis
    m = 4 # The upper bound on the network delay
    T_int = max(n, m) 

    intervals = []
    for i in range (1, key_chain_length+1):
        intervals.append(T_int*i)

    key_chain = create_key_chain(private_seed=private_seed, N=key_chain_length)
    print(key_chain)

    sender_initial_time = time()
    # TODO: Need to figure out disclosure delay
    return Sender(initial_time=sender_initial_time, key_chain=key_chain, T_int=T_int, intervals=intervals)

last_interval_index = 0 
def send_message(message, sender_obj):
    message_time  = time()
    print(message_time)
    interval = floor((message_time - sender_obj.T0)/sender_obj.T_int)

    print(sender_obj.key_chain[len(sender_obj.key_chain)-interval-1])

    return

def boostrap_receiver(last_key, T_int, T0, chain_length, disclosure_delay):
    D_t = 0 # lag of receiver's clock with respect to the clock of the sender
    K_0 = last_key

    return

def main():
    private_seed = b"Hello world"
    N = 10
    message = b"crypt"

    sender_obj = sender_setup(private_seed=private_seed, key_chain_length=N)

    for i in range(0, N):
        # Test condition to see if it moves to the next interval   
        if i == 2:
            sleep(5)
        send_message(message=message, sender_obj=sender_obj)

if __name__ == "__main__":
    main()