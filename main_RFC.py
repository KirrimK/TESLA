#import dis
from hashlib import sha256 # blake2b, blake2s
import hmac
from time import time # perf_counter, sleep
from math import ceil, floor

class Sender:
    def __init__(self, initial_time: float, key_chain: list[str], T_int: int, intervals: list[float], disclosure_delay: int):
        self.T0: float = initial_time #start time of sender
        self.key_chain: list[str] = key_chain #[K_n,....,K_0] où K_(n-1) = sha256(K_n)
        self.T_int: int = T_int #time of an interval in seconds
        self.intervals: list[float] = intervals #list of inferior bound of each interval [T0, T0+T_int, ....]
        self.d: int = disclosure_delay #nb intervals to wait to get the key to authentify a certain message in a certain time interval

class Receiver:
    def __init__(self, time_difference: float, T0: float, T_int: int, disclosure_delay: int, sender_interval: int, key_chain_len: int, max_key: str, last_key_index: int):
        self.D_t: float = time_difference # represent max time delay for a message sent by S to reach R ?
        self.K_0: str = max_key #K_0 cf Sender
        self.T0: float = T0 #cf sender
        self.T_int: int = T_int #cf sender
        self.d: int = disclosure_delay #nb intervals to wait to get the key to authentify a certain message in a certain time interval
        self.sender_interval: int = sender_interval #interval dans lequel le sender se situe actuellement
        self.key_chain_len: int = key_chain_len
        self.last_key_index: int = last_key_index # position dans key_chain de la dernière clé dévoilée par le sender 
        self.buffer: list[tuple[int, bytes, bytes]] = []
        self.received_keys: list[str] = []

# def create_key_chain(private_seed, N, interval):
def create_key_chain(private_seed: bytes, N: int):
    key_chain: list[str] = []

    for i in range(0, N):
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

def sender_setup(private_seed: bytes, key_chain_length: int):
    n = 3 # Send a packet every n msec
    m = 4 # The upper bound on the network delay
    T_int = max(n, m) * 1000 # Measured in seconds, temps d'un interval

    intervals: list[float] = []
    # for i in range (1, key_chain_length + 1):
    #     intervals.append(T_int*i)

    """
    C'est fait après enfoction de la key_chain et de start_time
    """

    key_chain = create_key_chain(private_seed=private_seed, N=key_chain_length)
    print(key_chain)

    sender_initial_time = time() * 1000
    # TODO: Do we need to perform the check that disclosure_delay > 1 ?
    RTT = 2 #round trip time, choisit arbitrairement ici
    disclosure_delay = (ceil(RTT/T_int) + 1) # Measured in time intervals. This SHOULD NOT BE == 1 i.e. delay of one interval (see RFC 3.6)
    """ c'est le d partie 2.6 du papier"""

    # NOTE: Maybe better shifted start time?
    start_time = (time() * 1000) - disclosure_delay * T_int
    for i in range(0, key_chain_length):
        intervals.append(start_time + i * T_int)
    
    return Sender(initial_time=sender_initial_time, key_chain=key_chain, T_int=T_int, intervals=intervals, disclosure_delay=disclosure_delay)

def send_message(message: bytes, sender_obj: Sender, i: int):
    message_time  = time() * 1000
    # print(message_time)
    # interval = floor((message_time - sender_obj.T0) * 1.0/sender_obj.T_int)
    interval = floor((message_time - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int) 
    # print(interval)
    # print(sender_obj.d)


    # print(sender_obj.key_chain[len(sender_obj.key_chain)-interval-1])

    # if i == 0:
    #     hm = hmac.new(msg=message, key=sender_obj.key_chain[len(sender_obj.key_chain) - interval].encode(), digestmod=sha256)

    #     # NOTE: Is that correct? Shall we not attach a key to the first message?
    #     return (message, hm.digest(), None, interval)         
    # else:
    #     hm = hmac.new(msg=message, key=sender_obj.key_chain[len(sender_obj.key_chain) - interval].encode(), digestmod=sha256)

    #     disclosed_key_index = interval - sender_obj.d
    #     return (message, hm.digest(), sender_obj.key_chain[len(sender_obj.key_chain) - disclosed_key_index], interval)

    disclosed_key_index = interval - sender_obj.d
    # print(disclosed_key_index)

    # if disclosed_key_index == 0:
    #     hm = hmac.new(msg=message, key=sender_obj.key_chain[len(sender_obj.key_chain)-1].encode(), digestmod=sha256)
    #     return (message, hm.digest(), None, interval)
    # else:
    #     hm = hmac.new(msg=message, key=sender_obj.key_chain[len(sender_obj.key_chain)-interval].encode(), digestmod=sha256)
    #     return (message, hm.digest(), sender_obj.key_chain[len(sender_obj.key_chain)-disclosed_key_index-1], interval)

    # NOTE: Baed on the paper and the RFC the key for the MAC should be derived from the PRF (hash) of the key from the chain
    hm = hmac.new(msg=message, key=sender_obj.key_chain[len(sender_obj.key_chain) - interval].encode(), digestmod=sha256)
    return (message, hm.digest(), sender_obj.key_chain[len(sender_obj.key_chain) - disclosed_key_index - 1], interval)

    """
    un packet est de la forme
    ( message, hmac( message, k_i), kc_(N-1-(i-d) = K_(i+d) ), i)
    """

def boostrap_receiver(last_key: str, T_int: int, T0: float, chain_length: int, disclosure_delay: int, sender_interval: int):
    D_t = 100 # lag of receiver's clock with respect to the clock of the sender
    """
    La partie syncro est pas faite
    """
    K_0 = last_key
    T_zero = T0
    T_int = T_int

    sender_interval = sender_interval

    disclosure_delay = disclosure_delay

    last_key_index: int = sender_interval - sender_interval #On initialise à zéro

    return Receiver(time_difference=D_t, T0=T_zero, T_int=T_int, disclosure_delay=disclosure_delay, 
        sender_interval=sender_interval, key_chain_len=chain_length,max_key=K_0, last_key_index=last_key_index)

def receiver_find_interval(disclosed_key: str, last_key: str, disclosed_interval: int, key_chain_len: int):
    """
    disclosed_key == k_(i+d), last_key == K_0,  disclosed_interval == i aka l'interval dans lequel diclosed_key a été dévoilée, 
    Permet de retrouver la valeur de l'interval dans lequel à été envoyé le message donc i pour eviter de se fier au contenu du message
    """

    temp_key: str = disclosed_key
    # temp_key = max_key
    hash_operations: int = 0 # représente le nombre de derivation restante pour passer de K_(n-i+d) a K_0
    
    # NOTE: Still not sure if we start from K_N and go down to K_0 or the opossite.
    while (temp_key != last_key and disclosed_interval + hash_operations < key_chain_len):
        temp_key = sha256(temp_key.encode()).hexdigest()
        hash_operations += 1 # a la find on a hash_operatuions  = n-1-(i+d)

    if (disclosed_interval + hash_operations >= key_chain_len):
        print("ERROR: INVALID KEY")
    
    return disclosed_interval + hash_operations 

def key_chain_verification(disclosed_key: str, last_key: str, key_chain_len: int):
    temp_key = disclosed_key
    hash_operations = 0
    while (temp_key != last_key):
        temp_key = sha256(temp_key.encode()).hexdigest()
        hash_operations += 1
        if (hash_operations == key_chain_len and temp_key != last_key):
            return False
    
    return True

def receive_message(packet: tuple[bytes, bytes, str, int], receiver_obj: Receiver):

    # We need to determine in which interval the received packet is to preform the safety test later
    packet_interval = receiver_find_interval(disclosed_key=packet[2], last_key=receiver_obj.K_0, 
        disclosed_interval=packet[3], key_chain_len=receiver_obj.key_chain_len)
    
    sender_max: float = time() * 1000 + receiver_obj.D_t
    elapsed_intervals = floor((sender_max - receiver_obj.T0) * 1.0 / receiver_obj.T_int)

    estimated_sender_interval = receiver_obj.sender_interval + elapsed_intervals

    # If the packet is not safe, print a message(or discard it)
    # NOTE: Not sure if we should use d or D_t
    if estimated_sender_interval > packet_interval + receiver_obj.d: #cf 2.6 i + d > i'
        print("Packet at interval {0} is not safe".format(receiver_obj.sender_interval))

    # Save the described triplet in the receiver's buffer
    receiver_obj.buffer.append((packet_interval, packet[0], packet[1]))

    disclosed_interval: int = packet_interval - receiver_obj.d

    # Test if the has already been disclosed 
    if disclosed_interval > receiver_obj.last_key_index:
        receiver_obj.received_keys.append(packet[2])
        receiver_obj.last_key_index = disclosed_interval

        
        verication_condition_1 = key_chain_verification(disclosed_key=packet[2], last_key=receiver_obj.K_0, 
            key_chain_len=receiver_obj.key_chain_len)
        
        # NOTE: This is a test condition
        # print(key_chain_verification(disclosed_key=packet[2], last_key="64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2b77232534a8aeca37f3c", key_chain_len=receiver_obj.key_chain_len))

        values_for_authentication = list(filter(lambda x : x[0] == disclosed_interval, receiver_obj.buffer))

        # TODO: If packets are authenticated, remove them from the buffer
        verication_condition_2 = False
        for value in values_for_authentication:
            prev_hmac: bytes = value[2]
            current_hmac = hmac.new(msg=value[1], key=packet[2].encode(), digestmod=sha256)

            if(not hmac.compare_digest(current_hmac.digest(), prev_hmac)):
                verication_condition_2 = False
            else:
                verication_condition_2 = True

        if verication_condition_1 and verication_condition_2:
            print("VERIFICATION SUCCEEDED")
        else:
            print("VERIFICATION FAILED")


def main():
    # TODO: Should be random
    private_seed = b"Hello world"
    N = 10
    message = b"crypt"

    sender_obj = sender_setup(private_seed=private_seed, key_chain_length=N)

    sender_interval = floor((time()* 1000 - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int) #interval dans lequel le sender se situe actuellement

    # NOTE: Maybe rename to max_key (for the max interval)
    # last_key = sender_obj.key_chain[sender_interval - sender_obj.d]
    last_key = sender_obj.key_chain[len(sender_obj.key_chain) - 1]
    # print(last_key)

    receiver_obj = boostrap_receiver(last_key=last_key, T_int=sender_obj.T_int, T0=sender_obj.T0,
      chain_length=N, disclosure_delay=sender_obj.d, sender_interval=sender_interval)

    for a in range(0, N):
        # Test condition to see if it moves to the next interval   
        # if i == 2:
        #     sleep(4)

        # if i == 5:
        #     sleep(4)

        # TODO: Create and adversarial case where we send a message with an already disclosed key

        packet = send_message(message=message, sender_obj=sender_obj, i=a)
        print(packet)
        print(len(packet[0])+len(packet[1])+len(packet[2].encode("ascii"))+len((packet[3].to_bytes(4, byteorder='big'))))

        receive_message(packet=packet, receiver_obj=receiver_obj)

    

if __name__ == "__main__":
    main()