from hashlib import blake2b, blake2s, sha256
import hmac
from time import perf_counter, time
from math import ceil, floor


# Scheme II: Create the key chain
def create_Key_Chain(private_seed, N):
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

# TODO: Do we need to apply multiple hashing here?
def key_verification(previous_key, current_key):
    verify = True if previous_key == sha256(current_key.encode()).hexdigest() else False
    print("Prev: {0}".format(previous_key))
    print("Curr: {0}".format(current_key))
    print("Hash_chain verification: {0}".format(verify))


def scheme_I_sender(message, private_seed, rate, i, T0):
    # # Perform the HMAC operation    
    attached_key = private_seed
    # if i != 0:
    #     private_seed = private_seed[:-1]
    # private_seed = private_seed+i.to_bytes(1, 'big')

    print("CALC {0}".format(private_seed))

    # Scheme I:
    hm = hmac.new(msg=message, key=private_seed, digestmod=sha256)

    h = sha256()
    h.update(private_seed)
    commitment = h.hexdigest()

    # Scheme I: Ti = T0 + i/r
    r = rate # One packet every 1 second

    # Append the message, the HMAC and the previous key
    # Special condition: since for the first message there is no previous key
    if i == 0:        
        Ti = T0 + i/r
        # TODO: Move that to a tuple for now, it is easier to do the operations
        # TODO: Have to add the commitment to the key for Scheme I
        sent_message = (message, hm.digest(), None, commitment,  Ti)

    else:        
        Ti = T0 + i/r
        attached_key = attached_key[:-1]
        attached_key = attached_key + (i-1).to_bytes(1, 'big')
        # TODO: Move that to a tuple for now, it is easier to do the operations
        # TODO: Have to add the commitment to the key for Scheme I        
        sent_message = (message, hm.digest(), attached_key, commitment,  Ti)

    return sent_message

def scheme_II_sender(message, rate, i, T0, key_chain):

    hm = hmac.new(msg=message, key=key_chain[i].encode(), digestmod=sha256)

    r = rate # One packet every 1 second

    # Append the message, the HMAC and the previous key
    # Special condition: since for the first message there is no previous key
    if i == 0:        
        Ti = T0 + i/r
        # TODO: Move that to a tuple for now, it is easier to do the operations        
        sent_message = (message, hm.digest(), None, Ti)


    else:        
        Ti = T0 + i/r
        # TODO: Move that to a tuple for now, it is easier to do the operations
        sent_message = (message, hm.digest(), key_chain[i-1], Ti)

    return sent_message

def scheme_III_sender(message, rate, i, T0, delay, key_chain):

    hm = hmac.new(msg=message, key=key_chain[i].encode(), digestmod=sha256)

    r = rate # One packet every 1 second

    # Scheme III
    if( i-delay >= 0):
        Ti = T0 + i/r
        sent_message =  (message, hm.digest(), key_chain[i-delay], Ti)
    else:
        Ti = T0 + i/r
        sent_message = (message, hm.digest(), None, Ti)

    return sent_message

def scheme_IV_sender(message, key_chain, i, T0, T_delta, disclosure_lag):

    # Scheme IV: The calulated interval
    sender_current_time = time()
    interval = floor((sender_current_time-T0)/T_delta)

    # Scheme IV artificial delay so the message verification will fail later
    # We choose the next key in the chain for this demonstration
    # if i == 1:
    #     interval = 1
    #     disclosure_lag = 3

    # NOTE: Based on the paper and the RFC this should have another PRF (or hash function) appplied
    # to the key of the chain as a good measure to prevent cryptographic weakness from key reuse
    hm = hmac.new(msg=message, key=key_chain[interval-disclosure_lag].encode(), digestmod=sha256)

    sent_message = (message, hm.digest(), key_chain[interval-disclosure_lag], interval)

    # print(sent_message)
    # print("Previous key {0}".format(attached_key))
    # print("Current key {0}".format(private_seed))

    return sent_message



def scheme_I_receiver(received_message, i, verifier_list, delta_t, Arr_Ti):
    message_for_verification = verifier_list[i-1]
    print(message_for_verification)
    # prev_message = message_for_verification[:5]
    prev_message = message_for_verification[0]

    # print(prev_message)         
    prev_hm = message_for_verification[1]   
    # print(prev_hm)
    prev_key = received_message[2]
    # print(prev_key)

    prev_commit = message_for_verification[3]
    # print(prev_commit)

    current_commit = received_message[3]
    # print(current_commit)

    current_Ti = received_message[4]
    # print(current_Ti) 

    delta_t = 1

    # print("ArrTi of previous: {0}".format(message_for_verification[4]))
    # print("delta_t: {0}".format(delta_t))
    # print("ArrTi + delta_t: {0}".format(message_for_verification[4]+delta_t))
    # print("current_Ti: {0}".format(current_Ti))
    

    verify_1 = False
    # Scheme I-II: Security condition
    if (Arr_Ti + delta_t) < current_Ti:
        verify_1 = True

    hm_val = hmac.new(msg=prev_message, key=prev_key, digestmod=sha256)
    # print("New digest {0}".format(hm_val.digest()))

    verify_2 = hmac.compare_digest(hm_val.digest(), prev_hm)

    # Check the commitment
    verify_3 = True if prev_commit == sha256(prev_key).hexdigest() else False
    
    return verify_1 and verify_2 and verify_3

def scheme_II_receiver(received_message, i, verifier_list, delta_t, Arr_Ti):
    
    message_for_verification = verifier_list[i-1]
    print(message_for_verification)
    # prev_message = message_for_verification[:5]
    prev_message = message_for_verification[0]

    # print(prev_message)         
    prev_hm = message_for_verification[1]   
    # print(prev_hm)
    prev_key = received_message[2]
    # print(prev_key)

    current_Ti = received_message[3]
    # print(current_Ti)

    # print("ArrTi of previous: {0}".format(message_for_verification[4]))
    # print("delta_t: {0}".format(delta_t))
    # print("ArrTi + delta_t: {0}".format(message_for_verification[4]+delta_t))
    # print("current_Ti: {0}".format(current_Ti))

    verify_1 = False
    # Scheme II: Security condition
    if (Arr_Ti + delta_t) < current_Ti:        
        verify_1 = True

    hm_val = hmac.new(msg=prev_message, key=prev_key.encode(), digestmod=sha256)
    # print("New digest {0}".format(hm_val.digest()))

    verify_2 = hmac.compare_digest(hm_val.digest(), prev_hm)
    
    return verify_1 and verify_2

def scheme_III_receiver(received_message, i, verifier_list, delta_t, Arr_Ti, delay):

    message_for_verification = verifier_list[i-delay]
    print(message_for_verification)
    # prev_message = message_for_verification[:5]
    prev_message = message_for_verification[0]

    # print(prev_message)         
    prev_hm = message_for_verification[1]   
    # print(prev_hm)
    prev_key = received_message[2]
    # print(prev_key)

    current_Ti = received_message[3]
    # print(current_Ti) 

    delta_t = 1

    # print("ArrTi of previous: {0}".format(message_for_verification[4]))
    # print("delta_t: {0}".format(delta_t))
    # print("ArrTi + delta_t: {0}".format(message_for_verification[4]+delta_t))
    # print("current_Ti: {0}".format(current_Ti))

    verify_1 = False
    # Scheme III: Security condition
    if (Arr_Ti + delta_t) < current_Ti:        
        verify_1 = True

    hm_val = hmac.new(msg=prev_message, key=prev_key.encode(), digestmod=sha256)
    # print("New digest {0}".format(hm_val.digest()))

    verify_2 = hmac.compare_digest(hm_val.digest(), prev_hm)
    
    return verify_1 and verify_2

def scheme_IV_receiver(received_message, i, verifier_list, delta_t, T0, T_delta, disclosure_lag):
   
    if i-disclosure_lag < 0:
        return

    message_for_verification = verifier_list[i-disclosure_lag]
    # print(message_for_verification)
    # prev_message = message_for_verification[:5]
    prev_message = message_for_verification[0]

    # print(prev_message)         
    prev_hm = message_for_verification[1]   
    # print(prev_hm)
    prev_key = received_message[2]

    sender_interval =  received_message[3]
   
    verify_1 = False
   
    receiver_current_time = time()
    # The following has notation i' in the paper
    max_allowed_interval = floor((receiver_current_time+delta_t-T0)/T_delta)
    
    # print("sender_interval {0}".format(sender_interval))
    # print("max_allowed_interval {0}".format(max_allowed_interval))

    if (sender_interval + disclosure_lag) > max_allowed_interval:
        verify_1 = True

    former_key = message_for_verification[3]
    current_key = prev_key
    key_verification(former_key, current_key)

    hm_val = hmac.new(msg=prev_message, key=prev_key.encode(), digestmod=sha256)
    # print("New digest {0}".format(hm_val.digest()))

    verify_2 = hmac.compare_digest(hm_val.digest(), prev_hm)
    
    return verify_1 and verify_2
    

def sender_actions(key_chain, i, rate, private_seed, T0 , delay, T_delta, disclosure_lag):    
    message = b"crypt"

    # Scheme I: using differetn keys - Just increasing the old one by 1 for simplicity
    # if i != 0:
    #     private_seed = private_seed[:-1]
    #     private_seed = private_seed + (i).to_bytes(1, 'big')
    # else:
    #     private_seed = private_seed + (i).to_bytes(1, 'big')

    # return scheme_I_sender(message=message, private_seed=private_seed, rate=rate, i=i, T0=T0)

    # return scheme_II_sender(message=message, rate=rate, i=i, T0=T0, key_chain=key_chain)

    # return scheme_III_sender(message=message, rate=rate, i=i, T0=T0, delay=delay, key_chain=key_chain)
        
    return scheme_IV_sender(message=message, key_chain=key_chain,  i=i, T0=T0, T_delta=T_delta, 
      disclosure_lag=disclosure_lag)

def receiver_actions(received_message, i, verifier_list, Arr_Ti, delay, T0, T_delta, disclosure_lag):
    delta_t = 1
    
    # return scheme_I_receiver(received_message=received_message, i=i, verifier_list=verifier_list,
        # delta_t=delta_t, Arr_Ti=Arr_Ti)

    # return scheme_II_receiver(received_message=received_message, i=i, verifier_list=verifier_list, 
    #     delta_t=delta_t, Arr_Ti=Arr_Ti,)

    # return scheme_III_receiver(received_message=received_message, i=i, verifier_list=verifier_list, 
    #     delta_t=delta_t, Arr_Ti=Arr_Ti, delay=delay)

    return scheme_IV_receiver(received_message=received_message, i=i, verifier_list=verifier_list, 
      delta_t=delta_t, T0=T0, T_delta=T_delta, disclosure_lag=disclosure_lag)

def main():
    # For the sake of simplicity we will increase the last number by one and append it
    private_seed = b"Hello world"

    N = 10

    key_chain = create_Key_Chain(private_seed, N)

    # print("Key chain: {0}".format(key_chain))

    verifier_list = []
    
    # Scheme I: The timestamp of the first packet from the sender
    T0 = time()
    
    # Packet rate
    r = 1

    # Scheme III: The delay parameter set by the sender based on packet rate
    # the maximum tolerable synchronization uncertainty and the maximum tolerable network delay
    delta_tMax = 4
    dNMax = 4
    delay = ceil((delta_tMax+dNMax)*r)

    # Scheme IV: The duration of each interval (in ms)
    # NOTE: T_delta must be determined according to the paper
    T_delta = 2
    delta_Max = delta_tMax+dNMax
    disclosure_lag = ceil(delta_Max/T_delta)
    # disclosure_lag = 2

    # print("disclosure_lag: {0}".format(disclosure_lag))

    sender_bench_time = []
    receiver_bench_time = []

    for i in range(0,N):
        # print(i)

        # print("=========SENDER=========")
        start = perf_counter()
        sent_message = sender_actions(key_chain=key_chain, i=i, rate=r, private_seed=private_seed, T0=T0 , delay=delay, T_delta=T_delta, disclosure_lag=disclosure_lag)         
        # print(sent_message)
        stop = perf_counter()
        sender_bench_time.append(stop-start)

        # Now the verifier should store and verify the message based on some next disclosed key
        # print("=========RECEIVER=========")
        start = perf_counter()
        Arr_Ti = time() # Just simulate the arrival time

        # NOTE: With the following, the verification for message 1 should now fail
        # if i == 3:
        #     Arr_Ti += 6
    
        received_message = sent_message + (Arr_Ti,)
        # print(received_message)
        # Special condition: If it is the first message there is no previous message to verify
        if i == 0:                
            verifier_list.append(received_message)
            continue       
        else:
            verifier_list.append(received_message)
            

        # Scheme III:
        # if( i-delay >= 0):
        #     verification = receiver_actions(received_message=received_message, i=i, 
        #         verifier_list=verifier_list, Arr_Ti=Arr_Ti, delay=delay, T_delta=T_delta, T0=T0, disclosure_lag=disclosure_lag)

        #     if not verification:
        #         print("Verification of message {0} failed".format(i-delay))
        #     else:
        #         print("Verification of message {0} achieved".format(i-delay))

        
        verification = receiver_actions(received_message=received_message, i=i, 
                verifier_list=verifier_list, Arr_Ti=Arr_Ti, delay=delay, T_delta=T_delta, 
                T0=T0, disclosure_lag=disclosure_lag)

        stop = perf_counter()
        receiver_bench_time.append(stop-start)

        if not verification:
            print("Verification of message {0} failed".format(i-disclosure_lag))
        # else:
        #     print("Verification of message {0} achieved".format(i-disclosure_lag))

        #  Just wait for #num second(s) before "sending" the next packet
        # time.sleep(2)
    
    sender_avg = sum(sender_bench_time) / len(sender_bench_time)
    print("Message sender AVG time for {0} messages is {1} sec".format(N-1, sender_avg))

    receiver_avg = sum(receiver_bench_time) / len(receiver_bench_time)
    print("Message verify time for {0} messages is {1} sec".format(N-1, receiver_avg))

if __name__ == "__main__":
    main()

    