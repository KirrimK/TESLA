from hashlib import sha256
import hmac

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

def receiver_find_interval(disclosed_key, last_key, disclosed_interval, key_chain_len):
    
    temp_key = disclosed_key
    # temp_key = max_key
    hash_operations = 0
    
    # NOTE: Still not sure if we start from K_N and go down to K_0 or the opossite.
    while (temp_key != last_key and disclosed_interval + hash_operations < key_chain_len):
    # while (temp_key != disclosed_key and disclosed_interval + hash_operations < key_chain_len):
        temp_key = sha256(temp_key.encode()).hexdigest()
        # temp_key = sha256(temp_key.encode()).hexdigest()
        hash_operations += 1

    if (disclosed_interval + hash_operations >= key_chain_len):
        print("ERROR: INVALID KEY")

def key_chain_verification(disclosed_key, last_key, key_chain_len):
    temp_key = disclosed_key
    hash_operations = 0
    while (temp_key != last_key):
        temp_key = sha256(temp_key.encode()).hexdigest()
        hash_operations += 1
        if (hash_operations == key_chain_len and temp_key != last_key):
            return False
    
    return True

def main():
    private_seed = b"Hello world"
    N = 10
    message = b"crypt"

    # SENDER SETUP
    key_chain = create_key_chain(private_seed=private_seed, N=N)
    print(key_chain)

    last_key = key_chain[len(key_chain) - 1]

    # BOOTSTRAP RECEIVER - Nothing to do in this step since we only exchange information about intervals, delay etc.

    values_for_authentication = []
    # NOTE: Say we split the intervals very one message for this very simple scenario
    for interval in range(0,10):
        # SEND MESSAGE
        if interval == 0:
            hm = hmac.new(msg=message, key=key_chain[len(key_chain) - interval - 1].encode(), digestmod=sha256)                        
            packet = (message, hm.digest(), None, interval)
        else:
            hm = hmac.new(msg=message, key=key_chain[len(key_chain) - interval -1].encode(), digestmod=sha256)
            packet = (message, hm.digest(), key_chain[len(key_chain) - interval], interval)

        # RECEIVE MESSAGE       
        values_for_authentication.append(packet)

        # print(values_for_authentication)

        # NOTE: Not sure if we need the following function since it does the same as the key verification one but included the check of the intervals
        # packet_interval = receiver_find_interval(disclosed_key=packet[2], last_key=receiver_obj.K_0, 
        #     disclosed_interval=packet[3], key_chain_len=receiver_obj.key_chain_len)

        if interval != 0:
            verication_condition_1 = key_chain_verification(disclosed_key=packet[2], last_key=last_key, 
                    key_chain_len=N)
            # print(verication_condition_1)

            # TODO: If packets are authenticated, remove them from the buffer
            verication_condition_2 = False
            for i, value in enumerate(values_for_authentication):
                # print(i, value)
                prev_hmac = value[1]
                current_hmac = hmac.new(msg=value[0], key=packet[2].encode(), digestmod=sha256).digest()

                if(not hmac.compare_digest(current_hmac, prev_hmac)):
                    verication_condition_2 = False
                else:
                    verication_condition_2 = True

                if verication_condition_1 and verication_condition_2:
                    print("VERIFICATION SUCCEEDED")
                else:
                    print("VERIFICATION FAILED")

                # Remove always the first element in the list
                values_for_authentication.pop(i)              

        

if __name__ == "__main__":
    main()