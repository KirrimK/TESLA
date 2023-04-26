#import dis
from hashlib import sha256, shake_256
import hmac
from time import time,sleep # perf_counter, sleep
from math import ceil, floor
import random

class Sender:
    def __init__(self, initial_time: float, key_chain: list[str], T_int: float, intervals: list[float], disclosure_delay: int, last_interval: float):
        self.T0: float = initial_time #start time of sender
        self.key_chain: list[str] = key_chain #[K_n,....,K_0] où K_(n-1) = sha256(K_n)
        self.T_int: float = T_int #time of an interval in seconds
        self.intervals: list[float] = intervals #list of inferior bound of each interval [T0, T0+T_int, ....]
        self.d: int = disclosure_delay #nb intervals to wait to get the key to authentify a certain message in a certain time interval
        self.last_T: float = last_interval
        self.key_chain_len: int = len(self.key_chain)
        self.previous_final_key: str|None = None

class Receiver:
    def __init__(self, time_difference: float, T0: float, T_int: float, disclosure_delay: int, sender_interval: int, key_chain_len: int, max_key: str, last_key_index: int):
        self.D_t: float = time_difference # represent max time delay for a message sent by S to reach R ?
        self.K_0: str = max_key #K_0 cf Sender
        self.T0: float = T0 #cf sender
        self.T_int: float = T_int #cf sender
        self.d: int = disclosure_delay #nb intervals to wait to get the key to authentify a certain message in a certain time interval
        self.sender_interval: int = sender_interval #interval dans lequel le sender se situe actuellement
        self.key_chain_len: int = key_chain_len
        self.last_key_index: int = last_key_index # position dans key_chain de la dernière clé dévoilée par le sender 
        self.buffer: list[tuple[int, bytes, bytes]] = []
        self.fishy_buffer: list[tuple[int, int, bytes, bytes]] = []
        self.authenticated_message: list[bytes] = []
        self.nb_authenticated_message: int = 0
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
    n = rate / 1000 #n message per second
    m = upper_bound_network_delay/1000 # The upper bound on the network delay in sec
    T_int = max(n, m) # Measured in ms, temps d'un interval
    intervals: list[float] = []
    
    key_chain = create_key_chain(private_seed=private_seed, N=key_chain_length)

    RTT = rtt/1000 #rtt in sec
    disclosure_delay = (ceil(RTT/T_int) + 1) # Measured in time intervals. This SHOULD NOT BE == 1 i.e. delay of one interval (see RFC 3.6)
    """ c'est le d partie 2.6 du papier"""
    print(f"disclosure delay: {disclosure_delay}")
    # NOTE: Maybe better shifted start time?
    start_time = time() #in second
    for i in range(0, key_chain_length):
        intervals.append(start_time + i * T_int)
    
    last_interval = start_time + key_chain_length*T_int
    return Sender(initial_time=start_time, key_chain=key_chain, T_int=T_int, intervals=intervals, disclosure_delay=disclosure_delay, last_interval=last_interval)

def send_message(message: bytes, sender_obj: Sender, end:bool):
    if end:
        key_i = sender_obj.key_chain[0] #K_i

        shake = shake_256()
        shake.update(key_i.encode())
        derived_key_i = shake.hexdigest(len(key_i)) #f'(K_i)
        hm = hmac.new(msg=message, key=derived_key_i.encode(), digestmod=sha256)
        return (message, hm.digest(), sender_obj.previous_final_key, -1)
    else:
        message_time  = time() #in sec
        interval = floor((message_time - sender_obj.intervals[0]) / sender_obj.T_int) #i
        #print("\033[93m" f"Current sender interval is: {floor((time() - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int)}"+ "\033[0m")
        i_minus_d = interval - sender_obj.d
        disclosed_key_index = i_minus_d if i_minus_d>0 else 0 #i-d
        key_i = sender_obj.key_chain[interval] #K_i

        shake = shake_256()
        shake.update(key_i.encode())
        derived_key_i = shake.hexdigest(len(key_i)) #f'(K_i)
        #print(f"derived key {interval}: {derived_key_i}")

        hm = hmac.new(msg=message, key=derived_key_i.encode(), digestmod=sha256)
        return (message, hm.digest(), sender_obj.key_chain[disclosed_key_index], interval)
    

    """
    un packet est de la forme
    ( message, hmac( message, f'(k_i)), k_(i-d), i)
    """

def send_fault_packet(message: bytes, sender_obj: Sender, type: int):
    if type == 0: #Packet with random k_i and disclosed key
        message_time  = time() #in sec
        interval = floor((message_time - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int) #i
        h = sha256()
        h.update(random.randbytes(8))
        key_i = h.hexdigest()

        h.update(random.randbytes(8))
        key_disclosed = h.hexdigest()

        shake = shake_256()
        shake.update(key_i.encode())
        derived_key_i = shake.hexdigest(len(key_i))

        hm = hmac.new(msg=message, key=derived_key_i.encode(), digestmod=sha256)
        return (message, hm.digest(), key_disclosed, interval)
    
    if type == 1: #Packet that reused an already disclosed key
        # NOTE: packets that are sent before interval d can still bypass authentication.
        message_time  = time() #in sec
        x = floor((message_time - sender_obj.intervals[0]) * 1.0 / sender_obj.T_int) - sender_obj.d - 1
        interval =  x if x>0 else 0

        disclosed_key_index = interval - sender_obj.d #i-d
        key_i = sender_obj.key_chain[interval] #K_i

        shake = shake_256()
        shake.update(key_i.encode())
        derived_key_i = shake.hexdigest(len(key_i)) #f'(K_i)

        hm = hmac.new(msg=message, key=derived_key_i.encode(), digestmod=sha256)
        return (message, hm.digest(), sender_obj.key_chain[disclosed_key_index], interval)
    
    if type == 2: #fake hmac with wrong key
        message_time  = time()#in sec
        interval = floor((message_time - sender_obj.intervals[0]) / sender_obj.T_int) #i

        i_minus_d = interval - sender_obj.d
        disclosed_key_index = i_minus_d if i_minus_d>0 else 0 #i-d

        "random k_i"
        h = sha256()
        h.update(random.randbytes(8))
        fake_key_i = h.hexdigest()

        shake = shake_256()
        shake.update(fake_key_i.encode())
        derived_key_i = shake.hexdigest(len(fake_key_i)) #f'(K_i)

        hm = hmac.new(msg=message, key=derived_key_i.encode(), digestmod=sha256)

        return (message, hm.digest(), sender_obj.key_chain[disclosed_key_index], interval)

def renew_key_chain(sender: Sender, time: float):
    
    private_seed = random.randbytes(12)
    sender.intervals = []
    sender.previous_final_key = sender.key_chain[-1]
    sender.key_chain = create_key_chain(private_seed=private_seed, N=sender.key_chain_len)

    for i in range(0, sender.key_chain_len):
        sender.intervals.append(time + i * sender.T_int)

    sender.T0 = time
    sender.last_T = time + sender.key_chain_len * sender.T_int

    


def boostrap_receiver(last_key: str, T_int: float, T0: float, chain_length: int, disclosure_delay: int, sender_interval: int, D_t: float):
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

def update_receiver(last_key: str, T_int: float, T0: float, sender_interval: int, receiver: Receiver):
    receiver.T0 = T0
    receiver.T_int = T_int
    receiver.K_0 = last_key
    receiver.sender_interval = sender_interval
    receiver.last_key_index = 0
    receiver.most_recent_disclosed_key = last_key
    receiver.known_keys = {0: last_key}


def receiver_check_safety(receiver_obj: Receiver, interval: int):
    """
    This function performs the safety test to check if the received packet HMAC is based on a still secret key 
   
    """
    sender_max: float = time() + receiver_obj.D_t#in second, upperbound of the time of arrival of the packet in sender referential
    highest_possible_sender_intervals = floor((sender_max - receiver_obj.T0) / receiver_obj.T_int)
    print(f"high: {highest_possible_sender_intervals}, i+d: {interval+receiver_obj.d}")
    return highest_possible_sender_intervals <= interval + receiver_obj.d #cf 2.6 i + d > i'
    

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
    
    #print(f"interval key: {interval_key} for message {packet_in_buffer[1], packet_in_buffer[0]}")
    shake = shake_256()
    shake.update(interval_key.encode())
    derived_key = shake.hexdigest(len(interval_key))
    #print(f"derived key {packet_in_buffer[0]}: {derived_key}")

    hm = hmac.new(msg=packet_in_buffer[1], key=derived_key.encode(), digestmod=sha256)
    #print(f"hm : {hm.digest()}, hmac: {packet_in_buffer[2]}")
    if hmac.compare_digest(hm.digest(), packet_in_buffer[2]): #message is authenticated
        #receiver.authenticated_message.append(packet_in_buffer[1])
        receiver.nb_authenticated_message += 1
        return True
    else:
        print('\033[91m' + f"message : {packet_in_buffer[1]} did not pass the hmac verification test (not a key renewal)" + "\033[0m")
        return False

def end_message_verification(packet_in_buffer: tuple[int,bytes,bytes], receiver: Receiver, final_key: str, final_interval: int):
    interval_key = final_key
    for i in range(final_interval-packet_in_buffer[0]):
            interval_key = sha256(interval_key.encode()).hexdigest()

    shake = shake_256()
    shake.update(interval_key.encode())
    derived_key = shake.hexdigest(len(interval_key))

    hm = hmac.new(msg=packet_in_buffer[1], key=derived_key.encode(), digestmod=sha256)
    #print(f"hm : {hm.digest()}, hmac: {packet_in_buffer[2]}")
    if hmac.compare_digest(hm.digest(), packet_in_buffer[2]): #message is authenticated
        #receiver.authenticated_message.append(packet_in_buffer[1])
        receiver.nb_authenticated_message += 1
        return True
    else:
        print('\033[91m' + f"message : {packet_in_buffer[1]} did not pass the hmac verification test (followinf a key renewal)" + "\033[0m")
        return False

def receive_message(packet: tuple[bytes, bytes, str, int], receiver_obj: Receiver):
    #print(f"Received packet: {packet}")
    if packet[3] == -1:
        # NOTE: need to add a way tocheck authenticity of this packet
        disclosed_interval = receiver_obj.key_chain_len-1
        shake = shake_256()
        shake.update(receiver_obj.K_0.encode())
        derived_key = shake.hexdigest(len(receiver_obj.K_0))
        hm = hmac.new(msg=packet[0], key=derived_key.encode(), digestmod=sha256)
        if hmac.compare_digest(hm.digest(), packet[1]): #message is authenticated
            can_authentify = list(filter(lambda p: p[0]<=disclosed_interval, receiver_obj.buffer))
            #print(f"authenticable: {can_authentify}")
            #update buffer
            receiver_obj.buffer = [packet for packet in receiver_obj.buffer if packet not in can_authentify]
            for i,p in enumerate(can_authentify):
                res = end_message_verification(packet_in_buffer=p, receiver=receiver_obj, final_key=packet[2], final_interval=disclosed_interval)
                    
                #print(f"Number of authentified message is {len(receiver_obj.authenticated_message)}")

        else:
            print('\033[91m' + f"message : {packet[0]} did not pass the hmac verification test" + "\033[0m")
            return False
    else:
        if not receiver_check_safety(receiver_obj=receiver_obj, interval=packet[3]): 
            print('\033[91m' + "Packet {0},{1},{2},{3} is not safe".format(packet[0],packet[1], packet[2], packet[3]) + "\033[0m")
            receiver_obj.fishy_buffer.append((0,packet[3], packet[0], packet[1])) #0 stands for "did not pass the safe packet test"
        else: #the packet seems legit
            
            #new key index test
            disclosed_interval: int = packet[3] - receiver_obj.d if packet[3] - receiver_obj.d > 0 else 0#i-d
            if packet[3] <= receiver_obj.last_key_index and len(receiver_obj.known_keys)>2:
                #print("key is already known") # key has already been disclosed
                message_verification(packet_in_buffer=(packet[3], packet[0], packet[1]), receiver=receiver_obj)
                #print(f"Number of authentified message is {len(receiver_obj.authenticated_message)}")
            else:
                #print("key is not known")
                #it's a new key, gotta check if it's one of the key chain
                if not key_chain_verification(key=packet[2], most_recent_disclosed_key=receiver_obj.most_recent_disclosed_key, last_key_index=receiver_obj.last_key_index, disclosed_interval=disclosed_interval):
                    print('\033[91m' + f"message : {packet[0]} did not pass the key chain verification" + "\033[0m")
                    receiver_obj.fishy_buffer.append((1,packet[3], packet[0], packet[1])) #1 stands for "did not pass the key verification test"
                else:
                    #update most_recent_disclosed_key and last_key_index
                    if disclosed_interval>receiver_obj.last_key_index:
                        receiver_obj.last_key_index = disclosed_interval
                        receiver_obj.most_recent_disclosed_key = packet[2]
                        receiver_obj.known_keys[disclosed_interval] = packet[2]

                    #add current packet to buffer
                    receiver_obj.buffer.append((packet[3], packet[0], packet[1]))

                    #filter all the packets that can be authentified from the buffer
                    can_authentify = list(filter(lambda p: p[0]<=receiver_obj.last_key_index, receiver_obj.buffer))
                    #print(f"authenticable: {can_authentify}")
                    #update buffer
                    receiver_obj.buffer = [packet for packet in receiver_obj.buffer if packet not in can_authentify]

                    #apply message verification to all can_authentify message
                    for i,p in enumerate(can_authentify):
                        res = message_verification(packet_in_buffer=p, receiver=receiver_obj)
                    
                    #print(f"Number of authentified message is {len(receiver_obj.authenticated_message)}")



private_seed = b"Hello world"
N = 10
rate = 0.05 #sendet send a packer every rate msec
sender_obj = sender_setup(private_seed=private_seed, key_chain_length=N, rate=rate, upper_bound_network_delay=1, rtt=1)
sender_time = time()
sender_interval = floor((sender_time - sender_obj.intervals[0]) / sender_obj.T_int) #interval dans lequel le sender se situe actuellement

last_key = sender_obj.key_chain[0]
D_t = 0 # in sec
receiver_obj = boostrap_receiver(last_key=last_key, T_int=sender_obj.T_int, T0=sender_obj.T0,
    chain_length=N, disclosure_delay=sender_obj.d, sender_interval=sender_interval, D_t = D_t)




def main():
    total_time_renew = 0
    total_time_process = 0 
    nb_renewal = 0
    sleep((sender_obj.d+1)*sender_obj.T_int)
    nb_message = 10000
    start = time()
    for a in range(0, nb_message):
        if a%1000 == 0:
            print(a)
        message_time  = time() #in sec
        #check if there's enought keys left
        if message_time >= sender_obj.last_T - sender_obj.d * sender_obj.T_int:
            nb_renewal += 1
            start_time_renew = time()
            renew_key_chain(sender_obj, message_time)
            update_receiver(last_key=sender_obj.key_chain[0], T_int=sender_obj.T_int, T0=sender_obj.T0, sender_interval=0, receiver=receiver_obj)
            packet = send_message(message=b"Disclosing previous key chain", sender_obj=sender_obj, end=True)
            receive_message(packet=packet, receiver_obj=receiver_obj) #type: ignore
            end_time_renew = time()
            #print(f"Time to update key chain is: {end_time_renew-start_time_renew}")
            total_time_renew += end_time_renew-start_time_renew

        start_time = time()
        packet = send_message(message=f"{a}".encode(encoding='UTF-8'), sender_obj=sender_obj, end=False)
        receive_message(packet=packet, receiver_obj=receiver_obj) # type: ignore
        end_time = time()
        #print(f"Time to update send packet and process it is: {end_time-start_time}")
        total_time_process += end_time-start_time

        sleep(rate/1000)
    end = time()
    #print(f"This what could be authenticated: {receiver_obj.authenticated_message}")
    print(f"The number of messages authenticated is : {receiver_obj.nb_authenticated_message}")
    print(f"Those are the fishy packets: {receiver_obj.fishy_buffer}")
    print(f"Those are the packets that still require authentication: {receiver_obj.buffer}")
    
    print((receiver_obj.nb_authenticated_message+len(receiver_obj.buffer))/nb_message*100)

    print(f"average processing time for a message is: {total_time_process/nb_message}")
    print(f"average renewal time: {total_time_renew/nb_renewal}")
    print(f"total time is: {end-start}")

if __name__ == "__main__":
    main()