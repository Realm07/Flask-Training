def encoder(STRING_TO_ENCODE:str, SECRET_KEY:str, ALGORITHM:str):
    SEED_VAL = 12
    ENCODED_VAL = SECRET_KEY
    if ALGORITHM == "AMA":
        
        for ch in STRING_TO_ENCODE:
            ENCODED_VAL = ENCODED_VAL[0:SEED_VAL] + ch + ENCODED_VAL[SEED_VAL+1]
    else:
        i = 0
        while(i<len(SECRET_KEY)):
            if i%2==0:
                ENCODED_VAL[i] = chr(ord(ENCODED_VAL[i])+1)

    return ENCODED_VAL

