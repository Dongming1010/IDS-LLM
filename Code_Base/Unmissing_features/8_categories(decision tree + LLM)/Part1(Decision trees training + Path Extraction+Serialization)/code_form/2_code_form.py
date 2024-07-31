#Target Lables:(BenignTraffic, Brute_Force, DDoS, DoS, Mirai, Recon, Spoofing, Web-Based):
def predict(flow_duration, Header_Length, Protocol_Type, Duration, Rate, Srate, Drate, fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, ece_flag_number, cwr_flag_number, ack_count, syn_count, fin_count, urg_count, rst_count, HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IPv, LLC, Tot_sum, Min, Max, AVG, Std, Tot_size, IAT, Number, Magnitue, Radius, Covariance, Variance, Weight):
    dict = {}
    threshholds = []
    if Variance <= 0.39:
        dict['Variance'] = Variance
        threshholds.append(['Variance', '<=', 0.39])
        if Tot_sum <= 3517.28:
            dict['Tot_sum'] = Tot_sum
            threshholds.append(['Tot_sum', '<=', 3517.28])
            if Header_Length <= 79.93:
                dict['Header_Length'] = Header_Length
                threshholds.append(['Header_Length', '<=', 79.93])
                if TCP <= 0.5:
                    dict['TCP'] = TCP
                    threshholds.append(['TCP', '<=', 0.5])
                    if Protocol_Type <= 1.5:
                        dict['Protocol_Type'] = Protocol_Type
                        threshholds.append(['Protocol_Type', '<=', 1.5])
                        if LLC <= 0.5:
                            dict['LLC'] = LLC
                            threshholds.append(['LLC', '<=', 0.5])
                            if Srate <= 0.23:
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '<=', 0.23])
                                if Rate <= 0.14:
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '<=', 0.14])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Rate > 0.14
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '>', 0.14])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if Srate > 0.23
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '>', 0.23])
                                return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                        else:  # if LLC > 0.5
                            dict['LLC'] = LLC
                            threshholds.append(['LLC', '>', 0.5])
                            if Radius <= 1.72:
                                dict['Radius'] = Radius
                                threshholds.append(['Radius', '<=', 1.72])
                                return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Radius > 1.72
                                dict['Radius'] = Radius
                                threshholds.append(['Radius', '>', 1.72])
                                if Min <= 54.76:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 54.76])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Min > 54.76
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 54.76])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if Protocol_Type > 1.5
                        dict['Protocol_Type'] = Protocol_Type
                        threshholds.append(['Protocol_Type', '>', 1.5])
                        if Srate <= 1.44:
                            dict['Srate'] = Srate
                            threshholds.append(['Srate', '<=', 1.44])
                            if Tot_sum <= 1404.5:
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '<=', 1404.5])
                                return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Tot_sum > 1404.5
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '>', 1404.5])
                                return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                        else:  # if Srate > 1.44
                            dict['Srate'] = Srate
                            threshholds.append(['Srate', '>', 1.44])
                            if Max <= 362.18:
                                dict['Max'] = Max
                                threshholds.append(['Max', '<=', 362.18])
                                return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Max > 362.18
                                dict['Max'] = Max
                                threshholds.append(['Max', '>', 362.18])
                                return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                else:  # if TCP > 0.5
                    dict['TCP'] = TCP
                    threshholds.append(['TCP', '>', 0.5])
                    if Duration <= 60.77:
                        dict['Duration'] = Duration
                        threshholds.append(['Duration', '<=', 60.77])
                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                    else:  # if Duration > 60.77
                        dict['Duration'] = Duration
                        threshholds.append(['Duration', '>', 60.77])
                        if fin_flag_number <= 0.5:
                            dict['fin_flag_number'] = fin_flag_number
                            threshholds.append(['fin_flag_number', '<=', 0.5])
                            if IAT <= 83009724.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 83009724.0])
                                if Weight <= 135.2:
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '<=', 135.2])
                                    if Number <= 6.81:
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '<=', 6.81])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if Number > 6.81
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '>', 6.81])
                                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Weight > 135.2
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '>', 135.2])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if IAT > 83009724.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 83009724.0])
                                if Variance <= 0.3:
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '<=', 0.3])
                                    if rst_flag_number <= 0.5:
                                        dict['rst_flag_number'] = rst_flag_number
                                        threshholds.append(['rst_flag_number', '<=', 0.5])
                                        return [[0.00000000e+00, 0.00000000e+00, 9.99137931e-01, 0.00000000e+00,  0.00000000e+00, 8.62068966e-04, 0.00000000e+00, 0.00000000e+00]], dict, threshholds
                                    else:  # if rst_flag_number > 0.5
                                        dict['rst_flag_number'] = rst_flag_number
                                        threshholds.append(['rst_flag_number', '>', 0.5])
                                        return [[0. , 0. , 0.1, 0. , 0. , 0.9, 0. , 0. ]], dict, threshholds
                                else:  # if Variance > 0.3
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '>', 0.3])
                                    if fin_count <= 0.15:
                                        dict['fin_count'] = fin_count
                                        threshholds.append(['fin_count', '<=', 0.15])
                                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if fin_count > 0.15
                                        dict['fin_count'] = fin_count
                                        threshholds.append(['fin_count', '>', 0.15])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                        else:  # if fin_flag_number > 0.5
                            dict['fin_flag_number'] = fin_flag_number
                            threshholds.append(['fin_flag_number', '>', 0.5])
                            return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
            else:  # if Header_Length > 79.93
                dict['Header_Length'] = Header_Length
                threshholds.append(['Header_Length', '>', 79.93])
                if Magnitue <= 11.42:
                    dict['Magnitue'] = Magnitue
                    threshholds.append(['Magnitue', '<=', 11.42])
                    if Number <= 7.33:
                        dict['Number'] = Number
                        threshholds.append(['Number', '<=', 7.33])
                        if urg_count <= 0.25:
                            dict['urg_count'] = urg_count
                            threshholds.append(['urg_count', '<=', 0.25])
                            return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                        else:  # if urg_count > 0.25
                            dict['urg_count'] = urg_count
                            threshholds.append(['urg_count', '>', 0.25])
                            if fin_count <= 0.05:
                                dict['fin_count'] = fin_count
                                threshholds.append(['fin_count', '<=', 0.05])
                                if syn_flag_number <= 0.5:
                                    dict['syn_flag_number'] = syn_flag_number
                                    threshholds.append(['syn_flag_number', '<=', 0.5])
                                    if syn_count <= 1.3:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 1.3])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if syn_count > 1.3
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 1.3])
                                        return [[0.04, 0.44, 0.  , 0.  , 0.  , 0.04, 0.12, 0.36]], dict, threshholds
                                else:  # if syn_flag_number > 0.5
                                    dict['syn_flag_number'] = syn_flag_number
                                    threshholds.append(['syn_flag_number', '>', 0.5])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if fin_count > 0.05
                                dict['fin_count'] = fin_count
                                threshholds.append(['fin_count', '>', 0.05])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                    else:  # if Number > 7.33
                        dict['Number'] = Number
                        threshholds.append(['Number', '>', 7.33])
                        if IAT <= 83033560.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 83033560.0])
                            if Tot_size <= 50.01:
                                dict['Tot_size'] = Tot_size
                                threshholds.append(['Tot_size', '<=', 50.01])
                                if Number <= 9.33:
                                    dict['Number'] = Number
                                    threshholds.append(['Number', '<=', 9.33])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Number > 9.33
                                    dict['Number'] = Number
                                    threshholds.append(['Number', '>', 9.33])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Tot_size > 50.01
                                dict['Tot_size'] = Tot_size
                                threshholds.append(['Tot_size', '>', 50.01])
                                return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if IAT > 83033560.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 83033560.0])
                            if Duration <= 59.44:
                                dict['Duration'] = Duration
                                threshholds.append(['Duration', '<=', 59.44])
                                if urg_count <= 17.6:
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '<=', 17.6])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if urg_count > 17.6
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '>', 17.6])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if Duration > 59.44
                                dict['Duration'] = Duration
                                threshholds.append(['Duration', '>', 59.44])
                                if Weight <= 193.08:
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '<=', 193.08])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Weight > 193.08
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '>', 193.08])
                                    if rst_count <= 105.55:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 105.55])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.96428571,  0.03571429, 0.   ]], dict, threshholds
                                    else:  # if rst_count > 105.55
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 105.55])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                else:  # if Magnitue > 11.42
                    dict['Magnitue'] = Magnitue
                    threshholds.append(['Magnitue', '>', 11.42])
                    if Magnitue <= 16.52:
                        dict['Magnitue'] = Magnitue
                        threshholds.append(['Magnitue', '<=', 16.52])
                        if IAT <= 0.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 0.0])
                            if Srate <= 364.06:
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '<=', 364.06])
                                if syn_count <= 0.1:
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '<=', 0.1])
                                    if Magnitue <= 11.48:
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '<=', 11.48])
                                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if Magnitue > 11.48
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '>', 11.48])
                                        return [[0.05797101, 0.   , 0.   , 0.   , 0.   , 0.01449275,  0.92753623, 0.   ]], dict, threshholds
                                else:  # if syn_count > 0.1
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '>', 0.1])
                                    if HTTPS <= 0.5:
                                        dict['HTTPS'] = HTTPS
                                        threshholds.append(['HTTPS', '<=', 0.5])
                                        return [[0.  , 0.25, 0.  , 0.  , 0.  , 0.5 , 0.  , 0.25]], dict, threshholds
                                    else:  # if HTTPS > 0.5
                                        dict['HTTPS'] = HTTPS
                                        threshholds.append(['HTTPS', '>', 0.5])
                                        return [[0.17241379, 0.05172414, 0.   , 0.   , 0.   , 0.25862069,  0.17241379, 0.34482759]], dict, threshholds
                            else:  # if Srate > 364.06
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '>', 364.06])
                                if AVG <= 65.98:
                                    dict['AVG'] = AVG
                                    threshholds.append(['AVG', '<=', 65.98])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if AVG > 65.98
                                    dict['AVG'] = AVG
                                    threshholds.append(['AVG', '>', 65.98])
                                    if syn_count <= 1.3:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 1.3])
                                        return [[0.01796407, 0.   , 0.   , 0.   , 0.   , 0.   ,  0.98203593, 0.   ]], dict, threshholds
                                    else:  # if syn_count > 1.3
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 1.3])
                                        return [[0.05555556, 0.11111111, 0.   , 0.   , 0.   , 0.05555556,  0.61111111, 0.16666667]], dict, threshholds
                        else:  # if IAT > 0.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 0.0])
                            if ack_flag_number <= 0.5:
                                dict['ack_flag_number'] = ack_flag_number
                                threshholds.append(['ack_flag_number', '<=', 0.5])
                                if Min <= 84.4:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 84.4])
                                    if Number <= 7.5:
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '<=', 7.5])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if Number > 7.5
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '>', 7.5])
                                        return [[0.   , 0.   , 0.08510638, 0.90425532, 0.   , 0.0106383 ,  0.   , 0.   ]], dict, threshholds
                                else:  # if Min > 84.4
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 84.4])
                                    if urg_count <= 0.0:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 0.0])
                                        return [[0.   , 0.   , 0.   , 0.125, 0.   , 0.   , 0.875, 0.   ]], dict, threshholds
                                    else:  # if urg_count > 0.0
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 0.0])
                                        return [[0. , 0. , 0.5, 0.5, 0. , 0. , 0. , 0. ]], dict, threshholds
                            else:  # if ack_flag_number > 0.5
                                dict['ack_flag_number'] = ack_flag_number
                                threshholds.append(['ack_flag_number', '>', 0.5])
                                if Weight <= 193.08:
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '<=', 193.08])
                                    if ack_count <= 0.3:
                                        dict['ack_count'] = ack_count
                                        threshholds.append(['ack_count', '<=', 0.3])
                                        return [[0.5255102 , 0.06887755, 0.00510204, 0.00765306, 0.   , 0.08163265,  0.20153061, 0.10969388]], dict, threshholds
                                    else:  # if ack_count > 0.3
                                        dict['ack_count'] = ack_count
                                        threshholds.append(['ack_count', '>', 0.3])
                                        return [[0.03448276, 0.4137931 , 0.   , 0.   , 0.   , 0.44827586,  0.06896552, 0.03448276]], dict, threshholds
                                else:  # if Weight > 193.08
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '>', 193.08])
                                    if Min <= 71.4:
                                        dict['Min'] = Min
                                        threshholds.append(['Min', '<=', 71.4])
                                        return [[0.14857143, 0.02857143, 0.   , 0.   , 0.   , 0.12571429,  0.51428571, 0.18285714]], dict, threshholds
                                    else:  # if Min > 71.4
                                        dict['Min'] = Min
                                        threshholds.append(['Min', '>', 71.4])
                                        return [[0.04347826, 0.   , 0.   , 0.   , 0.   , 0.   ,  0.95652174, 0.   ]], dict, threshholds
                    else:  # if Magnitue > 16.52
                        dict['Magnitue'] = Magnitue
                        threshholds.append(['Magnitue', '>', 16.52])
                        if Protocol_Type <= 6.83:
                            dict['Protocol_Type'] = Protocol_Type
                            threshholds.append(['Protocol_Type', '<=', 6.83])
                            if Header_Length <= 8176.57:
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '<=', 8176.57])
                                return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Header_Length > 8176.57
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '>', 8176.57])
                                if Srate <= 232.33:
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '<=', 232.33])
                                    if Std <= 283.93:
                                        dict['Std'] = Std
                                        threshholds.append(['Std', '<=', 283.93])
                                        return [[0.   , 0.   , 0.   , 0.33333333, 0.   , 0.33333333,  0.   , 0.33333333]], dict, threshholds
                                    else:  # if Std > 283.93
                                        dict['Std'] = Std
                                        threshholds.append(['Std', '>', 283.93])
                                        return [[0.75, 0.  , 0.  , 0.  , 0.  , 0.  , 0.25, 0.  ]], dict, threshholds
                                else:  # if Srate > 232.33
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '>', 232.33])
                                    if Tot_size <= 354.9:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 354.9])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if Tot_size > 354.9
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 354.9])
                                        return [[0.09090909, 0.   , 0.   , 0.   , 0.   , 0.09090909,  0.81818182, 0.   ]], dict, threshholds
                        else:  # if Protocol_Type > 6.83
                            dict['Protocol_Type'] = Protocol_Type
                            threshholds.append(['Protocol_Type', '>', 6.83])
                            if Variance <= 0.2:
                                dict['Variance'] = Variance
                                threshholds.append(['Variance', '<=', 0.2])
                                if Tot_size <= 378.72:
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '<=', 378.72])
                                    if Number <= 7.27:
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '<=', 7.27])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if Number > 7.27
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '>', 7.27])
                                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Tot_size > 378.72
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '>', 378.72])
                                    return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                            else:  # if Variance > 0.2
                                dict['Variance'] = Variance
                                threshholds.append(['Variance', '>', 0.2])
                                if Magnitue <= 26.36:
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '<=', 26.36])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Magnitue > 26.36
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '>', 26.36])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
        else:  # if Tot_sum > 3517.28
            dict['Tot_sum'] = Tot_sum
            threshholds.append(['Tot_sum', '>', 3517.28])
            if Tot_size <= 898.52:
                dict['Tot_size'] = Tot_size
                threshholds.append(['Tot_size', '<=', 898.52])
                if Tot_sum <= 3874.0:
                    dict['Tot_sum'] = Tot_sum
                    threshholds.append(['Tot_sum', '<=', 3874.0])
                    if Tot_size <= 425.04:
                        dict['Tot_size'] = Tot_size
                        threshholds.append(['Tot_size', '<=', 425.04])
                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if Tot_size > 425.04
                        dict['Tot_size'] = Tot_size
                        threshholds.append(['Tot_size', '>', 425.04])
                        return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                else:  # if Tot_sum > 3874.0
                    dict['Tot_sum'] = Tot_sum
                    threshholds.append(['Tot_sum', '>', 3874.0])
                    if Covariance <= 661932.61:
                        dict['Covariance'] = Covariance
                        threshholds.append(['Covariance', '<=', 661932.61])
                        return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                    else:  # if Covariance > 661932.61
                        dict['Covariance'] = Covariance
                        threshholds.append(['Covariance', '>', 661932.61])
                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
            else:  # if Tot_size > 898.52
                dict['Tot_size'] = Tot_size
                threshholds.append(['Tot_size', '>', 898.52])
                if TCP <= 0.5:
                    dict['TCP'] = TCP
                    threshholds.append(['TCP', '<=', 0.5])
                    if Max <= 1224.5:
                        dict['Max'] = Max
                        threshholds.append(['Max', '<=', 1224.5])
                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                    else:  # if Max > 1224.5
                        dict['Max'] = Max
                        threshholds.append(['Max', '>', 1224.5])
                        if Magnitue <= 49.94:
                            dict['Magnitue'] = Magnitue
                            threshholds.append(['Magnitue', '<=', 49.94])
                            return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                        else:  # if Magnitue > 49.94
                            dict['Magnitue'] = Magnitue
                            threshholds.append(['Magnitue', '>', 49.94])
                            if Srate <= 398.9:
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '<=', 398.9])
                                if Min <= 1342.0:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 1342.0])
                                    if flow_duration <= 0.57:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 0.57])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if flow_duration > 0.57
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 0.57])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Min > 1342.0
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 1342.0])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if Srate > 398.9
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '>', 398.9])
                                if Header_Length <= 901472.06:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 901472.06])
                                    if AVG <= 1338.72:
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '<=', 1338.72])
                                        return [[0. , 0. , 0. , 0. , 0. , 0. , 0.2, 0.8]], dict, threshholds
                                    else:  # if AVG > 1338.72
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '>', 1338.72])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.33333333,  0.66666667, 0.   ]], dict, threshholds
                                else:  # if Header_Length > 901472.06
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 901472.06])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                else:  # if TCP > 0.5
                    dict['TCP'] = TCP
                    threshholds.append(['TCP', '>', 0.5])
                    if urg_count <= 891.1:
                        dict['urg_count'] = urg_count
                        threshholds.append(['urg_count', '<=', 891.1])
                        if HTTP <= 0.5:
                            dict['HTTP'] = HTTP
                            threshholds.append(['HTTP', '<=', 0.5])
                            if rst_count <= 465.5:
                                dict['rst_count'] = rst_count
                                threshholds.append(['rst_count', '<=', 465.5])
                                if psh_flag_number <= 0.5:
                                    dict['psh_flag_number'] = psh_flag_number
                                    threshholds.append(['psh_flag_number', '<=', 0.5])
                                    if Weight <= 141.55:
                                        dict['Weight'] = Weight
                                        threshholds.append(['Weight', '<=', 141.55])
                                        return [[0.07843137, 0.15686275, 0.   , 0.   , 0.   , 0.05882353,  0.07843137, 0.62745098]], dict, threshholds
                                    else:  # if Weight > 141.55
                                        dict['Weight'] = Weight
                                        threshholds.append(['Weight', '>', 141.55])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.02564103,  0.02564103, 0.94871795]], dict, threshholds
                                else:  # if psh_flag_number > 0.5
                                    dict['psh_flag_number'] = psh_flag_number
                                    threshholds.append(['psh_flag_number', '>', 0.5])
                                    if Srate <= 218.09:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 218.09])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.16666667,  0.16666667, 0.66666667]], dict, threshholds
                                    else:  # if Srate > 218.09
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 218.09])
                                        return [[0.1, 0. , 0. , 0. , 0. , 0.1, 0.7, 0.1]], dict, threshholds
                            else:  # if rst_count > 465.5
                                dict['rst_count'] = rst_count
                                threshholds.append(['rst_count', '>', 465.5])
                                if flow_duration <= 9.13:
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '<=', 9.13])
                                    if Tot_size <= 1599.65:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 1599.65])
                                        return [[0.10810811, 0.05405405, 0.   , 0.   , 0.   , 0.05405405,  0.13513514, 0.64864865]], dict, threshholds
                                    else:  # if Tot_size > 1599.65
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 1599.65])
                                        return [[0.1875, 0.    , 0.    , 0.    , 0.    , 0.    , 0.8125, 0.    ]], dict, threshholds
                                else:  # if flow_duration > 9.13
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '>', 9.13])
                                    if Srate <= 11.33:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 11.33])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if Srate > 11.33
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 11.33])
                                        return [[0.82352941, 0.01960784, 0.   , 0.   , 0.   , 0.05882353,  0.03921569, 0.05882353]], dict, threshholds
                        else:  # if HTTP > 0.5
                            dict['HTTP'] = HTTP
                            threshholds.append(['HTTP', '>', 0.5])
                            if AVG <= 2934.0:
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '<=', 2934.0])
                                if Srate <= 2289.03:
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '<=', 2289.03])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if Srate > 2289.03
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '>', 2289.03])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if AVG > 2934.0
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '>', 2934.0])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                    else:  # if urg_count > 891.1
                        dict['urg_count'] = urg_count
                        threshholds.append(['urg_count', '>', 891.1])
                        if Min <= 1359.2:
                            dict['Min'] = Min
                            threshholds.append(['Min', '<=', 1359.2])
                            return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                        else:  # if Min > 1359.2
                            dict['Min'] = Min
                            threshholds.append(['Min', '>', 1359.2])
                            return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
    else:  # if Variance > 0.39
        dict['Variance'] = Variance
        threshholds.append(['Variance', '>', 0.39])
        if IAT <= 166602848.0:
            dict['IAT'] = IAT
            threshholds.append(['IAT', '<=', 166602848.0])
            if IAT <= 166551400.0:
                dict['IAT'] = IAT
                threshholds.append(['IAT', '<=', 166551400.0])
                if ack_flag_number <= 0.5:
                    dict['ack_flag_number'] = ack_flag_number
                    threshholds.append(['ack_flag_number', '<=', 0.5])
                    if TCP <= 0.5:
                        dict['TCP'] = TCP
                        threshholds.append(['TCP', '<=', 0.5])
                        if Tot_size <= 286.65:
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '<=', 286.65])
                            if IAT <= 166499176.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 166499176.0])
                                if Header_Length <= 114323.2:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 114323.2])
                                    if Variance <= 0.91:
                                        dict['Variance'] = Variance
                                        threshholds.append(['Variance', '<=', 0.91])
                                        return [[0.09892473, 0.2562724 , 0.00179211, 0.01397849, 0.   , 0.14193548,  0.11326165, 0.37383513]], dict, threshholds
                                    else:  # if Variance > 0.91
                                        dict['Variance'] = Variance
                                        threshholds.append(['Variance', '>', 0.91])
                                        return [[0.   , 0.   , 0.   , 0.00548446, 0.023766  , 0.5630713 ,  0.   , 0.40767824]], dict, threshholds
                                else:  # if Header_Length > 114323.2
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 114323.2])
                                    if urg_count <= 20.65:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 20.65])
                                        return [[0.06130268, 0.   , 0.   , 0.00383142, 0.00766284, 0.02298851,  0.88122605, 0.02298851]], dict, threshholds
                                    else:  # if urg_count > 20.65
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 20.65])
                                        return [[0.45390071, 0.07801418, 0.   , 0.0141844 , 0.   , 0.21276596,  0.17730496, 0.06382979]], dict, threshholds
                            else:  # if IAT > 166499176.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 166499176.0])
                                return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if Tot_size > 286.65
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '>', 286.65])
                            if Number <= 7.15:
                                dict['Number'] = Number
                                threshholds.append(['Number', '<=', 7.15])
                                if Protocol_Type <= 13.95:
                                    dict['Protocol_Type'] = Protocol_Type
                                    threshholds.append(['Protocol_Type', '<=', 13.95])
                                    if flow_duration <= 74.14:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 74.14])
                                        return [[0.32110092, 0.03669725, 0.00917431, 0.   , 0.   , 0.09174312,  0.43119266, 0.11009174]], dict, threshholds
                                    else:  # if flow_duration > 74.14
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 74.14])
                                        return [[0.03571429, 0.35714286, 0.   , 0.   , 0.   , 0.10714286,  0.28571429, 0.21428571]], dict, threshholds
                                else:  # if Protocol_Type > 13.95
                                    dict['Protocol_Type'] = Protocol_Type
                                    threshholds.append(['Protocol_Type', '>', 13.95])
                                    if Duration <= 34.8:
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '<=', 34.8])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if Duration > 34.8
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '>', 34.8])
                                        return [[0.00940439, 0.0031348 , 0.   , 0.   , 0.   , 0.   ,  0.96238245, 0.02507837]], dict, threshholds
                            else:  # if Number > 7.15
                                dict['Number'] = Number
                                threshholds.append(['Number', '>', 7.15])
                                if Covariance <= 209448.2:
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '<=', 209448.2])
                                    if Variance <= 0.97:
                                        dict['Variance'] = Variance
                                        threshholds.append(['Variance', '<=', 0.97])
                                        return [[0.   , 0.   , 0.00469484, 0.00469484, 0.98591549, 0.00469484,  0.   , 0.   ]], dict, threshholds
                                    else:  # if Variance > 0.97
                                        dict['Variance'] = Variance
                                        threshholds.append(['Variance', '>', 0.97])
                                        return [[0.48648649, 0.   , 0.   , 0.   , 0.   , 0.45945946,  0.   , 0.05405405]], dict, threshholds
                                else:  # if Covariance > 209448.2
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '>', 209448.2])
                                    if Weight <= 193.08:
                                        dict['Weight'] = Weight
                                        threshholds.append(['Weight', '<=', 193.08])
                                        return [[0.   , 0.   , 0.94512195, 0.01829268, 0.03658537, 0.   ,  0.   , 0.   ]], dict, threshholds
                                    else:  # if Weight > 193.08
                                        dict['Weight'] = Weight
                                        threshholds.append(['Weight', '>', 193.08])
                                        return [[0.71428571, 0.   , 0.   , 0.   , 0.   , 0.2  ,  0.   , 0.08571429]], dict, threshholds
                    else:  # if TCP > 0.5
                        dict['TCP'] = TCP
                        threshholds.append(['TCP', '>', 0.5])
                        if Tot_size <= 68.7:
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '<=', 68.7])
                            if Srate <= 9.22:
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '<=', 9.22])
                                if syn_count <= 1.19:
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '<=', 1.19])
                                    if Max <= 56.21:
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '<=', 56.21])
                                        return [[0. , 0. , 0.5, 0.5, 0. , 0. , 0. , 0. ]], dict, threshholds
                                    else:  # if Max > 56.21
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '>', 56.21])
                                        return [[0.   , 0.04651163, 0.02325581, 0.04651163, 0.   , 0.86046512,  0.   , 0.02325581]], dict, threshholds
                                else:  # if syn_count > 1.19
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '>', 1.19])
                                    if rst_count <= 4.57:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 4.57])
                                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if rst_count > 4.57
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 4.57])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if Srate > 9.22
                                dict['Srate'] = Srate
                                threshholds.append(['Srate', '>', 9.22])
                                if Min <= 47.0:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 47.0])
                                    return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Min > 47.0
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 47.0])
                                    if syn_count <= 1.0:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 1.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.99754902,  0.00245098, 0.   ]], dict, threshholds
                                    else:  # if syn_count > 1.0
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 1.0])
                                        return [[0.1, 0.1, 0. , 0.3, 0. , 0.5, 0. , 0. ]], dict, threshholds
                        else:  # if Tot_size > 68.7
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '>', 68.7])
                            if syn_flag_number <= 0.5:
                                dict['syn_flag_number'] = syn_flag_number
                                threshholds.append(['syn_flag_number', '<=', 0.5])
                                if Tot_sum <= 936.3:
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '<=', 936.3])
                                    if Header_Length <= 50502.1:
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '<=', 50502.1])
                                        return [[0.06270627, 0.20462046, 0.00660066, 0.01320132, 0.   , 0.39273927,  0.08250825, 0.23762376]], dict, threshholds
                                    else:  # if Header_Length > 50502.1
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '>', 50502.1])
                                        return [[0.38095238, 0.19047619, 0.   , 0.   , 0.   , 0.35714286,  0.04761905, 0.02380952]], dict, threshholds
                                else:  # if Tot_sum > 936.3
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '>', 936.3])
                                    if Tot_size <= 417.53:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 417.53])
                                        return [[0.088, 0.028, 0.004, 0.048, 0.004, 0.624, 0.008, 0.196]], dict, threshholds
                                    else:  # if Tot_size > 417.53
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 417.53])
                                        return [[0.25 , 0.   , 0.21428571, 0.17857143, 0.   , 0.17857143,  0.10714286, 0.07142857]], dict, threshholds
                            else:  # if syn_flag_number > 0.5
                                dict['syn_flag_number'] = syn_flag_number
                                threshholds.append(['syn_flag_number', '>', 0.5])
                                if Tot_size <= 121.15:
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '<=', 121.15])
                                    if Tot_size <= 107.36:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 107.36])
                                        return [[0.   , 0.01886792, 0.   , 0.   , 0.   , 0.96226415,  0.01886792, 0.   ]], dict, threshholds
                                    else:  # if Tot_size > 107.36
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 107.36])
                                        return [[0.   , 0.   , 0.33333333, 0.   , 0.   , 0.66666667,  0.   , 0.   ]], dict, threshholds
                                else:  # if Tot_size > 121.15
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '>', 121.15])
                                    if Tot_size <= 153.2:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 153.2])
                                        return [[0.   , 0.   , 0.83333333, 0.16666667, 0.   , 0.   ,  0.   , 0.   ]], dict, threshholds
                                    else:  # if Tot_size > 153.2
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 153.2])
                                        return [[0. , 0. , 0. , 0.6, 0. , 0.4, 0. , 0. ]], dict, threshholds
                else:  # if ack_flag_number > 0.5
                    dict['ack_flag_number'] = ack_flag_number
                    threshholds.append(['ack_flag_number', '>', 0.5])
                    if IAT <= 166499168.0:
                        dict['IAT'] = IAT
                        threshholds.append(['IAT', '<=', 166499168.0])
                        if IAT <= 83199244.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 83199244.0])
                            if Header_Length <= 164437.34:
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '<=', 164437.34])
                                if fin_count <= 0.49:
                                    dict['fin_count'] = fin_count
                                    threshholds.append(['fin_count', '<=', 0.49])
                                    if SSH <= 0.5:
                                        dict['SSH'] = SSH
                                        threshholds.append(['SSH', '<=', 0.5])
                                        return [[0.13205467, 0.31305115, 0.00088183, 0.00595238, 0.   , 0.16776896,  0.10471781, 0.27557319]], dict, threshholds
                                    else:  # if SSH > 0.5
                                        dict['SSH'] = SSH
                                        threshholds.append(['SSH', '>', 0.5])
                                        return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if fin_count > 0.49
                                    dict['fin_count'] = fin_count
                                    threshholds.append(['fin_count', '>', 0.49])
                                    if Tot_sum <= 4667.86:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 4667.86])
                                        return [[0.0125523 , 0.041841  , 0.   , 0.0167364 , 0.   , 0.89539749,  0.0292887 , 0.0041841 ]], dict, threshholds
                                    else:  # if Tot_sum > 4667.86
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 4667.86])
                                        return [[0.    , 0.    , 0.0625, 0.875 , 0.    , 0.0625, 0.    , 0.    ]], dict, threshholds
                            else:  # if Header_Length > 164437.34
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '>', 164437.34])
                                if IAT <= 0.0:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 0.0])
                                    if IAT <= 0.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 0.0])
                                        return [[0.26031294, 0.0227596 , 0.   , 0.   , 0.   , 0.02702703,  0.6002845 , 0.08961593]], dict, threshholds
                                    else:  # if IAT > 0.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 0.0])
                                        return [[0.45631068, 0.04004854, 0.   , 0.   , 0.   , 0.07281553,  0.36407767, 0.06674757]], dict, threshholds
                                else:  # if IAT > 0.0
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 0.0])
                                    if syn_count <= 0.05:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 0.05])
                                        return [[0.56512141, 0.02428256, 0.   , 0.00220751, 0.   , 0.04415011,  0.33333333, 0.03090508]], dict, threshholds
                                    else:  # if syn_count > 0.05
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 0.05])
                                        return [[0.70373921, 0.06232023, 0.   , 0.00191755, 0.   , 0.1093001 ,  0.0949185 , 0.02780441]], dict, threshholds
                        else:  # if IAT > 83199244.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 83199244.0])
                            if Variance <= 0.97:
                                dict['Variance'] = Variance
                                threshholds.append(['Variance', '<=', 0.97])
                                if Magnitue <= 32.78:
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '<=', 32.78])
                                    if HTTPS <= 0.5:
                                        dict['HTTPS'] = HTTPS
                                        threshholds.append(['HTTPS', '<=', 0.5])
                                        return [[0.   , 0.   , 0.0109589 , 0.   , 0.0109589 , 0.97808219,  0.   , 0.   ]], dict, threshholds
                                    else:  # if HTTPS > 0.5
                                        dict['HTTPS'] = HTTPS
                                        threshholds.append(['HTTPS', '>', 0.5])
                                        return [[0.   , 0.   , 0.0212766 , 0.   , 0.08510638, 0.89361702,  0.   , 0.   ]], dict, threshholds
                                else:  # if Magnitue > 32.78
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '>', 32.78])
                                    if Header_Length <= 6183.24:
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '<=', 6183.24])
                                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if Header_Length > 6183.24
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '>', 6183.24])
                                        return [[0.   , 0.   , 0.01515152, 0.   , 0.15151515, 0.83333333,  0.   , 0.   ]], dict, threshholds
                            else:  # if Variance > 0.97
                                dict['Variance'] = Variance
                                threshholds.append(['Variance', '>', 0.97])
                                if rst_count <= 274.95:
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '<=', 274.95])
                                    if urg_count <= 0.55:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 0.55])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.98461538,  0.   , 0.01538462]], dict, threshholds
                                    else:  # if urg_count > 0.55
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 0.55])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.58986731,  0.   , 0.41013269]], dict, threshholds
                                else:  # if rst_count > 274.95
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '>', 274.95])
                                    if psh_flag_number <= 0.5:
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '<=', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.90789474,  0.   , 0.09210526]], dict, threshholds
                                    else:  # if psh_flag_number > 0.5
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                    else:  # if IAT > 166499168.0
                        dict['IAT'] = IAT
                        threshholds.append(['IAT', '>', 166499168.0])
                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
            else:  # if IAT > 166551400.0
                dict['IAT'] = IAT
                threshholds.append(['IAT', '>', 166551400.0])
                return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
        else:  # if IAT > 166602848.0
            dict['IAT'] = IAT
            threshholds.append(['IAT', '>', 166602848.0])
            if Tot_sum <= 1094.35:
                dict['Tot_sum'] = Tot_sum
                threshholds.append(['Tot_sum', '<=', 1094.35])
                if IAT <= 166850792.0:
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '<=', 166850792.0])
                    if Header_Length <= 25548.55:
                        dict['Header_Length'] = Header_Length
                        threshholds.append(['Header_Length', '<=', 25548.55])
                        if IAT <= 166846200.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 166846200.0])
                            return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                        else:  # if IAT > 166846200.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 166846200.0])
                            return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                    else:  # if Header_Length > 25548.55
                        dict['Header_Length'] = Header_Length
                        threshholds.append(['Header_Length', '>', 25548.55])
                        if syn_count <= 0.9:
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '<=', 0.9])
                            if Tot_size <= 88.65:
                                dict['Tot_size'] = Tot_size
                                threshholds.append(['Tot_size', '<=', 88.65])
                                return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if Tot_size > 88.65
                                dict['Tot_size'] = Tot_size
                                threshholds.append(['Tot_size', '>', 88.65])
                                if Srate <= 30.04:
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '<=', 30.04])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if Srate > 30.04
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '>', 30.04])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                        else:  # if syn_count > 0.9
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '>', 0.9])
                            if urg_count <= 6.1:
                                dict['urg_count'] = urg_count
                                threshholds.append(['urg_count', '<=', 6.1])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if urg_count > 6.1
                                dict['urg_count'] = urg_count
                                threshholds.append(['urg_count', '>', 6.1])
                                if Magnitue <= 11.71:
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '<=', 11.71])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if Magnitue > 11.71
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '>', 11.71])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                else:  # if IAT > 166850792.0
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '>', 166850792.0])
                    if IAT <= 167246296.0:
                        dict['IAT'] = IAT
                        threshholds.append(['IAT', '<=', 167246296.0])
                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                    else:  # if IAT > 167246296.0
                        dict['IAT'] = IAT
                        threshholds.append(['IAT', '>', 167246296.0])
                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
            else:  # if Tot_sum > 1094.35
                dict['Tot_sum'] = Tot_sum
                threshholds.append(['Tot_sum', '>', 1094.35])
                if Rate <= 35.62:
                    dict['Rate'] = Rate
                    threshholds.append(['Rate', '<=', 35.62])
                    if HTTPS <= 0.5:
                        dict['HTTPS'] = HTTPS
                        threshholds.append(['HTTPS', '<=', 0.5])
                        if Min <= 58.5:
                            dict['Min'] = Min
                            threshholds.append(['Min', '<=', 58.5])
                            if syn_flag_number <= 0.5:
                                dict['syn_flag_number'] = syn_flag_number
                                threshholds.append(['syn_flag_number', '<=', 0.5])
                                if Radius <= 95.15:
                                    dict['Radius'] = Radius
                                    threshholds.append(['Radius', '<=', 95.15])
                                    if Tot_sum <= 1252.5:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 1252.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.43333333,  0.45 , 0.11666667]], dict, threshholds
                                    else:  # if Tot_sum > 1252.5
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 1252.5])
                                        return [[0.   , 0.00188679, 0.   , 0.   , 0.   , 0.33773585,  0.20188679, 0.45849057]], dict, threshholds
                                else:  # if Radius > 95.15
                                    dict['Radius'] = Radius
                                    threshholds.append(['Radius', '>', 95.15])
                                    if Srate <= 22.41:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 22.41])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.18547141,  0.20092736, 0.61360124]], dict, threshholds
                                    else:  # if Srate > 22.41
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 22.41])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.05479452,  0.60273973, 0.34246575]], dict, threshholds
                            else:  # if syn_flag_number > 0.5
                                dict['syn_flag_number'] = syn_flag_number
                                threshholds.append(['syn_flag_number', '>', 0.5])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                        else:  # if Min > 58.5
                            dict['Min'] = Min
                            threshholds.append(['Min', '>', 58.5])
                            if rst_count <= 0.25:
                                dict['rst_count'] = rst_count
                                threshholds.append(['rst_count', '<=', 0.25])
                                if Magnitue <= 15.1:
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '<=', 15.1])
                                    if DNS <= 0.5:
                                        dict['DNS'] = DNS
                                        threshholds.append(['DNS', '<=', 0.5])
                                        return [[0. , 0. , 0. , 0. , 0. , 0.2, 0.8, 0. ]], dict, threshholds
                                    else:  # if DNS > 0.5
                                        dict['DNS'] = DNS
                                        threshholds.append(['DNS', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if Magnitue > 15.1
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '>', 15.1])
                                    if flow_duration <= 12.26:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 12.26])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.88888889, 0.11111111]], dict, threshholds
                                    else:  # if flow_duration > 12.26
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 12.26])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.05, 0.35, 0.6 ]], dict, threshholds
                            else:  # if rst_count > 0.25
                                dict['rst_count'] = rst_count
                                threshholds.append(['rst_count', '>', 0.25])
                                if Header_Length <= 66870.45:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 66870.45])
                                    if Radius <= 50.4:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 50.4])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if Radius > 50.4
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 50.4])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.06666667,  0.18809524, 0.7452381 ]], dict, threshholds
                                else:  # if Header_Length > 66870.45
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 66870.45])
                                    if urg_count <= 51.05:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 51.05])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.  , 0.85, 0.15]], dict, threshholds
                                    else:  # if urg_count > 51.05
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 51.05])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.075, 0.25 , 0.675]], dict, threshholds
                    else:  # if HTTPS > 0.5
                        dict['HTTPS'] = HTTPS
                        threshholds.append(['HTTPS', '>', 0.5])
                        if Std <= 670.22:
                            dict['Std'] = Std
                            threshholds.append(['Std', '<=', 670.22])
                            if Std <= 70.12:
                                dict['Std'] = Std
                                threshholds.append(['Std', '<=', 70.12])
                                if Min <= 59.8:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 59.8])
                                    if urg_count <= 179.1:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 179.1])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.28571429,  0.27142857, 0.44285714]], dict, threshholds
                                    else:  # if urg_count > 179.1
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 179.1])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.82758621,  0.17241379, 0.   ]], dict, threshholds
                                else:  # if Min > 59.8
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 59.8])
                                    if flow_duration <= 612.57:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 612.57])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.0952381 ,  0.52380952, 0.38095238]], dict, threshholds
                                    else:  # if flow_duration > 612.57
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 612.57])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                            else:  # if Std > 70.12
                                dict['Std'] = Std
                                threshholds.append(['Std', '>', 70.12])
                                if Header_Length <= 59558.6:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 59558.6])
                                    if Rate <= 2.25:
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '<=', 2.25])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.11111111,  0.04444444, 0.84444444]], dict, threshholds
                                    else:  # if Rate > 2.25
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '>', 2.25])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.12931034,  0.24568966, 0.625     ]], dict, threshholds
                                else:  # if Header_Length > 59558.6
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 59558.6])
                                    if IAT <= 167246408.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 167246408.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.02040816,  0.95918367, 0.02040816]], dict, threshholds
                                    else:  # if IAT > 167246408.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 167246408.0])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                        else:  # if Std > 670.22
                            dict['Std'] = Std
                            threshholds.append(['Std', '>', 670.22])
                            if Tot_sum <= 12664.95:
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '<=', 12664.95])
                                if urg_count <= 18.05:
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '<=', 18.05])
                                    if IAT <= 167249672.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 167249672.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.46153846,  0.15384615, 0.38461538]], dict, threshholds
                                    else:  # if IAT > 167249672.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 167249672.0])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if urg_count > 18.05
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '>', 18.05])
                                    if Max <= 2938.0:
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '<=', 2938.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.94444444, 0.05555556]], dict, threshholds
                                    else:  # if Max > 2938.0
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '>', 2938.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.14285714,  0.57142857, 0.28571429]], dict, threshholds
                            else:  # if Tot_sum > 12664.95
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '>', 12664.95])
                                if Tot_size <= 94.3:
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '<=', 94.3])
                                    if Magnitue <= 47.94:
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '<=', 47.94])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if Magnitue > 47.94
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '>', 47.94])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if Tot_size > 94.3
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '>', 94.3])
                                    if Radius <= 2461.64:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 2461.64])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.05714286,  0.85714286, 0.08571429]], dict, threshholds
                                    else:  # if Radius > 2461.64
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 2461.64])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.  , 0.25, 0.75]], dict, threshholds
                else:  # if Rate > 35.62
                    dict['Rate'] = Rate
                    threshholds.append(['Rate', '>', 35.62])
                    if urg_count <= 163.8:
                        dict['urg_count'] = urg_count
                        threshholds.append(['urg_count', '<=', 163.8])
                        if IAT <= 167246344.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 167246344.0])
                            if Duration <= 239.9:
                                dict['Duration'] = Duration
                                threshholds.append(['Duration', '<=', 239.9])
                                if flow_duration <= 1.56:
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '<=', 1.56])
                                    if Srate <= 742.53:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 742.53])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.10571429,  0.57428571, 0.32 ]], dict, threshholds
                                    else:  # if Srate > 742.53
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 742.53])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.01408451,  0.86619718, 0.11971831]], dict, threshholds
                                else:  # if flow_duration > 1.56
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '>', 1.56])
                                    if HTTP <= 0.5:
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '<=', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.04924875,  0.85475793, 0.09599332]], dict, threshholds
                                    else:  # if HTTP > 0.5
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '>', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.98461538, 0.01538462]], dict, threshholds
                            else:  # if Duration > 239.9
                                dict['Duration'] = Duration
                                threshholds.append(['Duration', '>', 239.9])
                                if Protocol_Type <= 8.75:
                                    dict['Protocol_Type'] = Protocol_Type
                                    threshholds.append(['Protocol_Type', '<=', 8.75])
                                    if IAT <= 166846232.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166846232.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.17391304, 0.82608696]], dict, threshholds
                                    else:  # if IAT > 166846232.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166846232.0])
                                        return [[0.    , 0.    , 0.    , 0.    , 0.    , 0.8125, 0.1875, 0.    ]], dict, threshholds
                                else:  # if Protocol_Type > 8.75
                                    dict['Protocol_Type'] = Protocol_Type
                                    threshholds.append(['Protocol_Type', '>', 8.75])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                        else:  # if IAT > 167246344.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 167246344.0])
                            return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                    else:  # if urg_count > 163.8
                        dict['urg_count'] = urg_count
                        threshholds.append(['urg_count', '>', 163.8])
                        if IAT <= 166729208.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 166729208.0])
                            return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                        else:  # if IAT > 166729208.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 166729208.0])
                            if IAT <= 166851008.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 166851008.0])
                                if IAT <= 166846248.0:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 166846248.0])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if IAT > 166846248.0
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 166846248.0])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if IAT > 166851008.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 166851008.0])
                                if Srate <= 81.36:
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '<=', 81.36])
                                    if IAT <= 167241960.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 167241960.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if IAT > 167241960.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 167241960.0])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if Srate > 81.36
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '>', 81.36])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
