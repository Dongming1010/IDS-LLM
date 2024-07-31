import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.tree import _tree
from sklearn.preprocessing import KBinsDiscretizer
import numpy as np
import re

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

def categorize_variance(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.2:
        return 'extremely low'
    elif value <= 0.3:
        return 'low'
    elif value <= 0.39:
        return 'midly low'
    elif value <= 0.91:
        return 'midly high'
    elif value <= 0.97:
        return 'high'
    else:
        return 'extremely high'
    
def categorize_tot_sum(value):
    if value == 0.0:
        return 'zero'
    elif value <= 936.3:
        return 'level 1'
    elif value <= 1094.35:
        return 'level 2'
    elif value <= 1252.5:
        return 'level 3'
    elif value <= 1404.5:
        return 'level 4'
    elif value <= 3517.28:
        return 'level 5'
    elif value <= 3874.0:
        return 'level 6'
    elif value <= 4667.86:
        return 'level 7'
    elif value <= 12664.95:
        return 'level 8'
    else:
        return 'level 9'

def categorize_header_length(value):
    if value == 0.0:
        return 'zero'
    elif value <= 79.93:
        return 'level 1'
    elif value <= 6183.24:
        return 'level 2'
    elif value <= 8176.57:
        return 'level 3'
    elif value <= 25548.55:
        return 'level 4'
    elif value <= 50502.1:
        return 'level 5'
    elif value <= 59558.6:
        return 'level 6'
    elif value <= 66870.45:
        return 'level 7'
    elif value <= 114323.2:
        return 'level 8'
    elif value <= 164437.34:
        return 'level 9'
    elif value <= 901472.06:
        return 'level 10'
    else:
        return 'level 11'

def categorize_srate(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.23:
        return 'level 1'
    elif value <= 1.44:
        return 'level 2'
    elif value <= 9.22:
        return 'level 3'
    elif value <= 11.33:
        return 'level 4'
    elif value <= 22.41:
        return 'level 5'
    elif value <= 30.04:
        return 'level 6'
    elif value <= 81.36:
        return 'level 7'
    elif value <= 218.09:
        return 'level 8'
    elif value <= 232.33:
        return 'level 9'
    elif value <= 364.06:
        return 'level 10'
    elif value <= 398.9:
        return 'level 11'
    elif value <= 742.53:
        return 'level 12'
    elif value <= 2289.03:
        return 'level 13'
    else:
        return 'level 14'

def categorize_rate(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.14:
        return 'low'
    elif value <= 2.25:
        return 'mildly low'
    elif value <= 35.62:
        return 'mildly high'
    else:
        return 'high'

def categorize_radius(value):
    if value == 0.0:
        return 'zero'
    elif value <= 1.72:
        return 'low'
    elif value <= 50.4:
        return 'mildly low'
    elif value <= 95.15:
        return 'medium'
    elif value <= 2461.64:
        return 'mildly high'
    else:
        return 'high'

def categorize_min(value):
    if value == 0.0:
        return 'zero'
    elif value <= 47.0:
        return 'level 1'
    elif value <= 54.76:
        return 'level 2'
    elif value <= 58.5:
        return 'level 3'
    elif value <= 59.8:
        return 'level 4'
    elif value <= 71.4:
        return 'level 5'
    elif value <= 84.4:
        return 'level 6'
    elif value <= 1342.0:
        return 'level 7'
    elif value <= 1359.2:
        return 'level 8'
    else:
        return 'level 9'

def categorize_max(value):
    if value == 0.0:
        return 'zero'
    elif value <= 56.21:
        return 'low'
    elif value <= 362.18:
        return 'mildly low'
    elif value <= 1224.5:
        return 'medium'
    elif value <= 2938.0:
        return 'mildly high'
    else:
        return 'high'

def categorize_duration(value):
    if value == 0.0:
        return 'zero'
    elif value <= 34.8:
        return 'low'
    elif value <= 59.44:
        return 'mildly low'
    elif value <= 60.77:
        return 'medium'
    elif value <= 239.9:
        return 'mildly high'
    else:
        return 'high'

def categorize_weight(value):
    if value == 0.0:
        return 'zero'
    elif value <= 135.2:
        return 'low'
    elif value <= 141.55:
        return 'mildly low'
    elif value <= 193.08:
        return 'mildly high'
    else:
        return 'high'

def categorize_number(value):
    if value == 0.0:
        return 'zero'
    elif value <= 6.81:
        return 'extremely low'
    elif value <= 7.15:
        return 'low'
    elif value <= 7.27:
        return 'mildly low'
    elif value <= 7.33:
        return 'medium'
    elif value <= 7.5:
        return 'mildly high'
    elif value <= 9.33:
        return 'high'
    else:
        return 'extremely high'

def categorize_fin_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.05:
        return 'low'
    elif value <= 0.15:
        return 'mildly low'
    elif value <= 0.49:
        return 'mildly high'
    else:
        return 'high'

def categorize_magnitude(value):
    if value == 0.0:
        return 'zero'
    elif value <= 11.42:
        return 'level 1'
    elif value <= 11.48:
        return 'level 2'
    elif value <= 11.71:
        return 'level 3'
    elif value <= 15.1:
        return 'level 4'
    elif value <= 16.52:
        return 'level 5'
    elif value <= 26.36:
        return 'level 6'
    elif value <= 32.78:
        return 'level 7'
    elif value <= 47.94:
        return 'level 8'
    elif value <= 49.94:
        return 'level 9'
    else:
        return 'level 10'

def categorize_urg_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.25:
        return 'level 1'
    elif value <= 0.55:
        return 'level 2'
    elif value <= 6.1:
        return 'level 3'
    elif value <= 17.6:
        return 'level 4'
    elif value <= 18.05:
        return 'level 5'
    elif value <= 20.65:
        return 'level 6'
    elif value <= 51.05:
        return 'level 7'
    elif value <= 163.8:
        return 'level 8'
    elif value <= 179.1:
        return 'level 9'
    elif value <= 891.1:
        return 'level 10'
    else:
        return 'level 11'

def categorize_syn_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.05:
        return 'extremely low'
    elif value <= 0.1:
        return 'low'
    elif value <= 0.9:
        return 'mildly low'
    elif value <= 1.0:
        return 'medium'
    elif value <= 1.19:
        return 'mildly high'
    elif value <= 1.3:
        return 'high'
    else:
        return 'extremely high'

def categorize_tot_size(value):
    if value == 0.0:
        return 'zero'
    elif value <= 50.01:
        return 'level 1'
    elif value <= 68.7:
        return 'level 2'
    elif value <= 88.65:
        return 'level 3'
    elif value <= 94.3:
        return 'level 4'
    elif value <= 107.36:
        return 'level 5'
    elif value <= 121.15:
        return 'level 6'
    elif value <= 153.2:
        return 'level 7'
    elif value <= 286.65:
        return 'level 8'
    elif value <= 354.9:
        return 'level 9'
    elif value <= 378.72:
        return 'level 10'
    elif value <= 417.53:
        return 'level 11'
    elif value <= 425.04:
        return 'level 12'
    elif value <= 898.52:
        return 'level 13'
    elif value <= 1599.65:
        return 'level 14'
    else:
        return 'level 15'

def categorize_rst_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.25:
        return 'extremely low'
    elif value <= 4.57:
        return 'low'
    elif value <= 105.55:
        return 'mildly low'
    elif value <= 274.95:
        return 'mildly high'
    elif value <= 465.5:
        return 'high'
    else:
        return 'extremely high'

def categorize_avg(value):
    if value == 0.0:
        return 'zero'
    elif value <= 65.98:
        return 'low'
    elif value <= 1338.72:
        return 'mildly low'
    elif value <= 2934.0:
        return 'mildly high'
    else:
        return 'high'

def categorize_ack_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.3:
        return 'low'
    else:
        return 'high'

def categorize_std(value):
    if value == 0.0:
        return 'zero'
    elif value <= 70.12:
        return 'low'
    elif value <= 283.93:
        return 'mildly low'
    elif value <= 670.22:
        return 'mildly high'
    else:
        return 'high'

def categorize_covariance(value):
    if value == 0.0:
        return 'zero'
    elif value <= 209448.2:
        return 'low'
    elif value <= 661932.61:
        return 'medium'
    else:
        return 'high'

def categorize_flow_duration(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.57:
        return 'extremely low'
    elif value <= 1.56:
        return 'low'
    elif value <= 9.13:
        return 'mildly low'
    elif value <= 12.26:
        return 'medium'
    elif value <= 74.14:
        return 'mildly high'
    elif value <= 612.57:
        return 'high'
    else:
        return 'extremely high'

def categorize_iat(value):
    if value == 0.0:
        return 'zero'
    if value <= 83199244.0:
        return 'extremely low'
    if value <= 166551400.0:
        return 'low'
    if value <= 166846200.0:
        return 'midly low'
    if value <= 166850792.0:
        return 'medium'
    if value <= 167246296.0:
        return 'midly high'
    if value <= 167249672.0:
        return 'high' 
    else:
        return 'extremely high'
    
feature_descriptions_zero = {
    'ts': "Timestamp",
    'flow_duration': "The Duration of the packet's flow",
    'Header_Length': "Packet header length",
    'Protocol_Type': "Protocol type",
    'Duration': "Time-to-Live",
    'Rate': "Rate of packet transmission",
    'Srate': "Rate of outbound packets transmission",
    'Drate': "Rate of inbound packets transmission",
    'fin_flag_number': "Count of FIN flags (which signal the end of data transmission)",
    'syn_flag_number': "Count of SYN flags (indicating the initiation of a TCP three-way handshake)",
    'rst_flag_number': "Count of RST flags (used for resetting connections)",
    'psh_flag_number': "Count of PSH flags (instructing to push buffered data to the receiving application)",
    'ack_flag_number': "Count of ACK flags (used to acknowledge packet receipts)",
    'ece_flag_number': "Count of ECE flags (indicating network congestion)",
    'cwr_flag_number': "Count of CWR flags (signaling reduced transmission rate due to congestion notification)",
    'ack_count': "Number of packets with an ACK flag",
    'syn_count': "Number of packets with a SYN flag",
    'fin_count': "Number of packets with a FIN flag",
    'urg_count': "Number of packets with an URG flag",
    'rst_count': "Number of packets with an RST flag",
    'HTTP': "Application layer protocol is HTTP",
    'HTTPS': "Application layer protocol is HTTPS",
    'DNS': "Application layer protocol is DNS",
    'Telnet': "Application layer protocol is Telnet",
    'SMTP': "Application layer protocol is SMTP",
    'SSH': "Application layer protocol is SSH",
    'IRC': "Application layer protocol is IRC",
    'TCP': "Transport layer protocol is TCP",
    'UDP': "Transport layer protocol is UDP",
    'DHCP': "Application layer protocol is DHCP",
    'ARP': "Link layer protocol is ARP",
    'ICMP': "Network layer protocol is ICMP",
    'IPv': "Network layer protocol is IP",
    'LLC': "Link layer protocol is LLC",
    'Tot_sum': "Total sum of packets lengths",
    'Min': "Minimum packet length in the flow",
    'Max': "Maximum packet length in the flow",
    'AVG': "Average packet length in the flow",
    'Std': "Standard deviation of packet length",
    'Tot_size': "Packet's length",
    'IAT': "The time difference between two consecutive packets",
    'Number': "The total number of packets",
    'Magnitue': "Magnitude (calculated as the mean of the average lengths of incoming and outgoing packets in the flow)",
    'Radius': "Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets)",
    'Covariance': "Covariance (coveriance of the lengths of incoming and outgoing packets)",
    'Variance': "Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets)",
    'Weight': "Weight (calculated as the product of the counts of incoming and outgoing packets)"
}

# used when value is zero
feature_descriptions = {
    'ts': "Timestamp",
    'flow_duration': "The Duration of the packet's flow",
    'Header_Length': "On a scale from Level 1 to Level 11, Packet header length",
    'Protocol_Type': "Protocol type",
    'Duration': "Time-to-Live",
    'Rate': "Rate of packet transmission",
    'Srate': "On a scale from Level 1 to Level 14, rate of outbound packets transmission",
    'Drate': "Rate of inbound packets transmission",
    'fin_flag_number': "Count of FIN flags (which signal the end of data transmission)",
    'syn_flag_number': "Count of SYN flags (indicating the initiation of a TCP three-way handshake)",
    'rst_flag_number': "Count of RST flags (used for resetting connections)",
    'psh_flag_number': "Count of PSH flags (instructing to push buffered data to the receiving application)",
    'ack_flag_number': "Count of ACK flags (used to acknowledge packet receipts)",
    'ece_flag_number': "Count of ECE flags (indicating network congestion)",
    'cwr_flag_number': "Count of CWR flags (signaling reduced transmission rate due to congestion notification)",
    'ack_count': "Number of packets with an ACK flag",
    'syn_count': "Number of packets with a SYN flag",
    'fin_count': "Number of packets with a FIN flag",
    'urg_count': "On a scale from Level 1 to Level 11, number of packets with an URG flag",
    'rst_count': "Number of packets with an RST flag",
    'HTTP': "Application layer protocol is HTTP",
    'HTTPS': "Application layer protocol is HTTPS",
    'DNS': "Application layer protocol is DNS",
    'Telnet': "Application layer protocol is Telnet",
    'SMTP': "Application layer protocol is SMTP",
    'SSH': "Application layer protocol is SSH",
    'IRC': "Application layer protocol is IRC",
    'TCP': "Transport layer protocol is TCP",
    'UDP': "Transport layer protocol is UDP",
    'DHCP': "Application layer protocol is DHCP",
    'ARP': "Link layer protocol is ARP",
    'ICMP': "Network layer protocol is ICMP",
    'IPv': "Network layer protocol is IP",
    'LLC': "Link layer protocol is LLC",
    'Tot_sum': "On a scale from Level 1 to Level 9, total sum of packets lengths",
    'Min': "On a scale from Level 1 to Level 9, Minimum packet length in the flow",
    'Max': "Maximum packet length in the flow",
    'AVG': "Average packet length in the flow",
    'Std': "Standard deviation of packet length",
    'Tot_size': "On a scale from Level 1 to Level 15, Packet's length",
    'IAT': "The time difference between two consecutive packets",
    'Number': "The total number of packets",
    'Magnitue': "On a scale from Level 1 to Level 10, Magnitude (calculated as the mean of the average lengths of incoming and outgoing packets in the flow)",
    'Radius': "Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets)",
    'Covariance': "Covariance (coveriance of the lengths of incoming and outgoing packets)",
    'Variance': "Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets)",
    'Weight': "Weight (calculated as the product of the counts of incoming and outgoing packets)"
}

numerical_features = [
    'flow_duration', 'Header_Length', 'Duration', 'Rate',
    'Srate', 'Drate', 'ack_count','syn_count','fin_count','urg_count',
    'rst_count','Tot_sum', 'Min', 'Max', 'AVG', 'Std',
    'Tot_size', 'IAT', 'Number', 'Magnitue', 'Radius',
    'Covariance', 'Variance', 'Weight', 
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number',
    'cwr_flag_number'
]

flag_features = [
    'HTTP', 'HTTPS', 'DNS', 'Telnet',
    'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
    'ICMP', 'IPv', 'LLC'
]

def create_description(row):
    descriptions = []
    # for numerical feature
    for feature in numerical_features:
        value = row.get(feature)
        if pd.notnull(value):  # Check if the feature is not NaN
            if value == "zero":
                descriptions.append(f"{feature_descriptions_zero.get(feature, feature)} is {value}.")
            else:
                descriptions.append(f"{feature_descriptions.get(feature, feature)} is {value}.")

    # flag
    for feature in flag_features:
        if row.get(feature) == 1:
            protocol_name = ' '.join(feature.split('_')).capitalize()
            descriptions.append(f"{feature_descriptions.get(feature, feature)}.")

    if pd.notnull(row.get("psh_flag_number")):
        value = row.get("psh_flag_number")
        if value == 1:
            descriptions.append("The psh(push) flag exists in this traffic")
            
    if pd.notnull(row.get("rst_flag_number")):
        value = row.get("rst_flag_number")
        rst_count = row.get("rst_count")
        if value == 1 and rst_count != "zero":
            descriptions.append("The rst(reset) flag exists in this traffic")
            
    if pd.notnull(row.get("ack_flag_number")):
        value = row.get("ack_flag_number")
        ack_count = row.get("ack_count")
        if value == 1 and ack_count != "zero":
            descriptions.append("The ack(Acknowledgment) flag exists in this traffic")
            
    if pd.notnull(row.get("syn_flag_number")):
        value = row.get("syn_flag_number")
        syn_count = row.get("syn_count")
        if value == 1 and syn_count != "zero":
            descriptions.append("The syn(Synchronize) flag exists in this traffic")

    if pd.notnull(row.get("fin_flag_number")):
        value = row.get("fin_flag_number")
        fin_count = row.get("fin_count")
        if value == 1 and fin_count != "zero":
            descriptions.append("The fin(Finish) flag exists in this traffic")
            
    return ' '.join(descriptions)

df = pd.read_csv('source/combined_test.csv')
df.rename(columns={'Tot sum': 'Tot_sum'}, inplace=True)
df.rename(columns={'Tot size': 'Tot_size'}, inplace=True)
df.rename(columns={'Protocol Type': 'Protocol_Type'}, inplace=True)

labels = ("BenignTraffic", "Brute_Force", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web-Based")

# Function to apply predictions and return the corresponding label
def get_prediction_label(row):
    prediction_probs, dict, thresholds = predict(*row[:-1])
    max_index = np.argmax(prediction_probs)
    return labels[max_index]

def get_prediction_prediction_accuracy(row):
    prediction_probs, results_dict, thresholds = predict(*row[:-2])

    # Define a mapping for names that differ in format
    name_mapping = {
        # 'Tot_sum': 'Tot sum',
        # 'Tot_size': 'Tot size',
        # 'Protocol_Type': 'Protocol Type'
    }
    
    # Convert thresholds into a readable string format with proper naming
    conditions_str = " and ".join([
        f"({name_mapping.get(condition[0], condition[0])} {condition[1]} {condition[2]})"
        for condition in thresholds
    ])
    search_string = f"if {conditions_str} then class:"
    # print(search_string)
    # Read the file and search for the pattern
    with open('natural_language_form/2_decision_tree_rule-9-natrual_language.txt', 'r') as file:
        for line in file:
            if search_string in line:
                # Extract probability
                prob_match = re.search(r"\(proba: (\d+\.\d+)%\)", line)
                if prob_match:
                    return float(prob_match.group(1))  # Return as float percentage
                else:
                    print("There is no prob matching")
    print(search_string)
    return None

def get_prediction_prediction_string(row):
    prediction_probs, results_dict, thresholds = predict(*row[:-3])

    # Define a mapping for names that differ in format
    name_mapping = {
        # 'Tot_sum': 'Tot sum',
        # 'Tot_size': 'Tot size',
        # 'Protocol_Type': 'Protocol Type'
    }
    
    # Convert thresholds into a readable string format with proper naming
    conditions_str = " and ".join([
        f"({name_mapping.get(condition[0], condition[0])} {condition[1]} {condition[2]})"
        for condition in thresholds
    ])
    search_string = f"if {conditions_str} then class:"

    # Read the file and search for the pattern
    with open('natural_language_form/2_decision_tree_rule-9-natrual_language.txt', 'r') as file:
        for line in file:
            if search_string in line:
                # Extract probability
                prob_match = re.search(r"\(proba: (\d+\.\d+)%\)", line)
                if prob_match:
                    return search_string  # Return as float percentage
                # else:
                #     print("here")
    #print(search_string)
    return None

def get_prediction_path(row):
    prediction_probs, dict, thresholds = predict(*row[:-4])

    if 'Variance' in dict:
        dict['Variance'] = categorize_variance(dict['Variance'])
    if 'Tot_sum' in dict:
        dict['Tot_sum'] = categorize_tot_sum(dict['Tot_sum'])
    if 'Header_Length' in dict:
        dict['Header_Length'] = categorize_header_length(dict['Header_Length'])
    if 'Srate' in dict:
        dict['Srate'] = categorize_srate(dict['Srate'])
    if 'Rate' in dict:
        dict['Rate'] = categorize_rate(dict['Rate'])
    if 'Radius' in dict:
        dict['Radius'] = categorize_radius(dict['Radius'])
    if 'Min' in dict:
        dict['Min'] = categorize_min(dict['Min'])
    if 'Max' in dict:
        dict['Max'] = categorize_max(dict['Max'])
    if 'Duration' in dict:
        dict['Duration'] = categorize_duration(dict['Duration'])
    if 'IAT' in dict:
        dict['IAT'] = categorize_iat(dict['IAT'])
    if 'Weight' in dict:
        dict['Weight'] = categorize_weight(dict['Weight'])
    if 'Number' in dict:
        dict['Number'] = categorize_number(dict['Number'])
    if 'fin_count' in dict:
        dict['fin_count'] = categorize_fin_count(dict['fin_count'])
    if 'Magnitue' in dict:
        dict['Magnitue'] = categorize_magnitude(dict['Magnitue'])
    if 'urg_count' in dict:
        dict['urg_count'] = categorize_urg_count(dict['urg_count'])
    if 'syn_count' in dict:
        dict['syn_count'] = categorize_syn_count(dict['syn_count'])
    if 'Tot_size' in dict:
        dict['Tot_size'] = categorize_tot_size(dict['Tot_size'])
    if 'rst_count' in dict:
        dict['rst_count'] = categorize_rst_count(dict['rst_count'])
    if 'AVG' in dict:
        dict['AVG'] = categorize_avg(dict['AVG'])
    if 'ack_count' in dict:
        dict['ack_count'] = categorize_ack_count(dict['ack_count'])
    if 'Std' in dict:
        dict['Std'] = categorize_std(dict['Std'])
    if 'Covariance' in dict:
        dict['Covariance'] = categorize_covariance(dict['Covariance'])
    if 'flow_duration' in dict:
        dict['flow_duration'] = categorize_flow_duration(dict['flow_duration'])

    if 'Protocol_Type' in dict:
        dict.pop('Protocol_Type')
    return create_description(dict)

def get_prediction_threholds(row):
    prediction_probs, dict, thresholds = predict(*row[:-5])
    return thresholds

# Apply the function to each row and create a new 'prediction' column with the results
df['prediction']= df.apply(lambda row: get_prediction_label(row), axis=1)
df['accuracy'] = df.apply(lambda row: get_prediction_prediction_accuracy(row), axis=1)
df['search_string'] = df.apply(lambda row: get_prediction_prediction_string(row), axis=1)
df['path'] = df.apply(lambda row: get_prediction_path(row), axis=1)
df['prediction_threholds'] = df.apply(lambda row: get_prediction_threholds(row), axis=1)

correct_predictions = (df['label'] == df['prediction']).sum()

total_predictions = len(df)

print(total_predictions)

accuracy = correct_predictions / total_predictions

print(f'Accuracy: {accuracy:.4f}')

partial_df = df.groupby('label').sample(n=625, random_state=42)

label_counts = partial_df['label'].value_counts()

print(label_counts)

partial_df.to_csv('processed/2_5000.csv', index=False)
percentage_matching = (partial_df['prediction'] == partial_df['label']).mean() * 100
mismatch = (partial_df['prediction'] != partial_df['label']).sum()
print(f"5000_accuracy: {percentage_matching:.2f}%")
print(f"mismatch: {mismatch}")