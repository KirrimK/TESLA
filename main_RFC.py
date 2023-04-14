#import dis
from hashlib import sha256, shake_256
import hmac
from time import time,sleep # perf_counter, sleep
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
        self.fishy_buffer: list[tuple[int, int, bytes, bytes]] = []
        self.authentified_message: list[bytes] = []
        self.most_recent_disclosed_key: str = self.K_0
        self.known_keys: dict[int, str] = {0: self.K_0}
    
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

    key_chain.reverse() #[K_0, K_1, ..., K_(N-1)= sha256(private_seed)]

    return  key_chain

def sender_setup(private_seed: bytes, key_chain_length: int, rate, upper_bound_network_delay, rtt):
    n = rate # Send a packet every n msec
    m = upper_bound_network_delay # The upper bound on the network delay
    T_int = max(n, m) # Measured in seconds, temps d'un interval

    intervals: list[float] = []
    
    key_chain = create_key_chain(private_seed=private_seed, N=key_chain_length)

    sender_initial_time = time()  #in second
    RTT = rtt #should be in sec too
    disclosure_delay = (ceil(RTT/T_int) + 1) # Measured in time intervals. This SHOULD NOT BE == 1 i.e. delay of one interval (see RFC 3.6)
    """ c'est le d partie 2.6 du papier"""
    print(disclosure_delay)
    # NOTE: Maybe better shifted start time?
    start_time = time() - disclosure_delay * T_int #in second
    for i in range(0, key_chain_length):
        intervals.append(start_time + i * T_int)
    
    return Sender(initial_time=sender_initial_time, key_chain=key_chain, T_int=T_int, intervals=intervals, disclosure_delay=disclosure_delay)

def send_message(message: bytes, sender_obj: Sender, i: int):
    message_time  = time() #in sec
    interval = floor((message_time - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int) #i
    print(sender_obj.T_int)

    disclosed_key_index = interval - sender_obj.d #i-d
    key_i = sender_obj.key_chain[interval] #K_i

    shake = shake_256()
    shake.update(key_i.encode())
    derived_key_i = shake_256().hexdigest(len(key_i)) #f'(K_i)

    hm = hmac.new(msg=message, key=derived_key_i.encode(), digestmod=sha256)
    return (message, hm.digest(), sender_obj.key_chain[disclosed_key_index], interval)

    """
    un packet est de la forme
    ( message, hmac( message, f'(k_i)), k_(i-d), i)
    """

def boostrap_receiver(last_key: str, T_int: int, T0: float, chain_length: int, disclosure_delay: int, sender_interval: int, D_t: float):
    #Assuming that synchronisation has been done already
    #Need to ad verification on last key (Signature checking)
    K_0 = last_key
    T_zero = T0
    T_int = T_int

    sender_interval = sender_interval

    disclosure_delay = disclosure_delay

    last_key_index: int = sender_interval - sender_interval #On initialise à zéro

    return Receiver(time_difference=D_t, T0=T_zero, T_int=T_int, disclosure_delay=disclosure_delay, 
        sender_interval=sender_interval, key_chain_len=chain_length,max_key=K_0, last_key_index=last_key_index)

def receiver_check_packet_interval(disclosed_key: str, last_key: str, interval: int, key_chain_len: int, disclosure_delay: int):
    temp_key: str = disclosed_key

    hash_operations: int = 0 #permet de calculer i-d
    
    while (temp_key != last_key and hash_operations + disclosure_delay <= interval):
        temp_key = sha256(temp_key.encode()).hexdigest()
        hash_operations += 1 

    if (interval > hash_operations + disclosure_delay):
        print("ERROR: INVALID PACKET OR SOMETHING IS FISHY ATLEAST (stated interval in packet does not work with disclosed_key)")
    
    return hash_operations + disclosure_delay #interval calculated with disclosed key

def receiver_check_safety(receiver_obj: Receiver, interval: int):
    """
    This function performs the safety test to check if the received packet HMAC is based on a still secret key 
   
    """
    sender_max: float = time() + receiver_obj.D_t #in second, upperbound of the time of arrival of the packet in sender referential
    highest_possible_sender_intervals = floor((sender_max - receiver_obj.T0)  / receiver_obj.T_int)

    return highest_possible_sender_intervals < interval + receiver_obj.d #cf 2.6 i + d > i'
    

def key_chain_verification(key: str, most_recent_disclosed_key: str, last_key_index: int, disclosed_interval: int): 
    temp_key = key
    hash_operations = 0
    while (temp_key != most_recent_disclosed_key):
        temp_key = sha256(temp_key.encode()).hexdigest()
        hash_operations += 1
        if (hash_operations == (disclosed_interval-last_key_index) and temp_key != most_recent_disclosed_key):
            return False
    
    return True

def message_verification(packet_in_buffer: tuple[int,bytes,bytes], receiver: Receiver):
    #Find or Compute the key for message
    if packet_in_buffer[0] in receiver.known_keys:
        interval_key = receiver.known_keys[packet_in_buffer[0]]
    else:
        interval_key = receiver.most_recent_disclosed_key
        for i in range(receiver.last_key_index-packet_in_buffer[0]):
            interval_key = sha256(interval_key.encode()).hexdigest()
    
    shake = shake_256()
    shake.update(interval_key.encode())
    derived_key = shake_256().hexdigest(len(interval_key))

    hm = hmac.new(msg=packet_in_buffer[1], key=derived_key.encode(), digestmod=sha256)

    if hmac.compare_digest(hm.digest(), packet_in_buffer[2]): #message is authenticated
        receiver.authentified_message.append(packet_in_buffer[1])
        return True
    else:
        return False

    

def receive_message(packet: tuple[bytes, bytes, str, int], receiver_obj: Receiver):

    # We need to determine in which interval the received packet is to preform the safety test later
    packet_interval = receiver_check_packet_interval(disclosed_key=packet[2], last_key=receiver_obj.K_0, 
                                             interval=packet[3], key_chain_len=receiver_obj.key_chain_len, disclosure_delay = receiver_obj.d)
    # If the packet is not safe, print a message(or discard it)
    if not receiver_check_safety(receiver_obj=receiver_obj, interval=packet_interval): 
        print("Packet {0},{1},{2},{3} is not safe".format(packet[0],packet[1], packet[2], packet[3]))
        receiver_obj.fishy_buffer.append((0,packet_interval, packet[0], packet[1])) #0 stands for "did not pass the safe packet test"
    else: #the packet seems legit
        
        #new key index test
        disclosed_interval: int = packet_interval - receiver_obj.d #i-d
        if disclosed_interval <= receiver_obj.last_key_index: # key has already been disclosed
            message_verification(packet_in_buffer=(disclosed_interval, packet[0], packet[1]), receiver=receiver_obj)
            print(f"Number of authentified message is {len(receiver_obj.authentified_message)}")
        else:
            #it's a new key, gotta check if it's one of the key chain
            if not key_chain_verification(key=packet[2], most_recent_disclosed_key=receiver_obj.most_recent_disclosed_key, last_key_index=receiver_obj.last_key_index, disclosed_interval=disclosed_interval):
                receiver_obj.fishy_buffer.append((1,packet_interval, packet[0], packet[1])) #1 stands for "did not pass the key verification test"
            else:
                #update most_recent_disclosed_key and last_key_index
                receiver_obj.last_key_index = disclosed_interval
                receiver_obj.most_recent_disclosed_key = packet[2]
                receiver_obj.known_keys[disclosed_interval] = packet[2]

                #add current packet to buffer
                receiver_obj.buffer.append((packet_interval, packet[0], packet[1]))

                #filter all the packets that can be authentified from the buffer
                can_authentify = filter(lambda p: p[0]<receiver_obj.last_key_index, receiver_obj.buffer)

                #update buffer
                receiver_obj.buffer = [packet for packet in receiver_obj.buffer if packet not in can_authentify]

                #apply message verification to all can_authentify message
                for i,p in enumerate(can_authentify):
                    message_verification(packet_in_buffer=p, receiver=receiver_obj)
                
                print(f"Number of authentified message is {len(receiver_obj.authentified_message)}")




        


def main():
    # TODO: Should be random
    private_seed = b"Hello world"
    N = 10
    message = b"crypthjkhkjhjhkjkjhgkhh"

    sender_obj = sender_setup(private_seed=private_seed, key_chain_length=N, rate=3, upper_bound_network_delay=0, rtt=2)

    sender_interval = floor((time()* 1000 - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int) #interval dans lequel le sender se situe actuellement

    # NOTE: Maybe rename to max_key (for the max interval)
    # last_key = sender_obj.key_chain[sender_interval - sender_obj.d]
    last_key = sender_obj.key_chain[0]
    # print(last_key)
    D_t = -60
    receiver_obj = boostrap_receiver(last_key=last_key, T_int=sender_obj.T_int, T0=sender_obj.T0,
      chain_length=N, disclosure_delay=sender_obj.d, sender_interval=sender_interval, D_t = D_t)

    for a in range(0, N):
        # Test condition to see if it moves to the next interval   
        # if i == 2:
        #     sleep(4)

        # if i == 5:
        #     sleep(4)

        # TODO: Create and adversarial case where we send a message with an already disclosed key

        packet = send_message(message=message, sender_obj=sender_obj, i=1)
        print(packet)
        #print(len(packet[1])+len(packet[2].encode("ascii"))+len((packet[3].to_bytes(4, byteorder='big'))))
        #print(type(packet[0]), type(packet[1]), type(packet[2]), type(packet[3]) )
        #print(len(packet[0]), len(packet[1]), len(packet[2]), len(packet[3].to_bytes(4, byteorder='big')) )
        receive_message(packet=packet, receiver_obj=receiver_obj)
        sleep(4)

    

if __name__ == "__main__":
    main()