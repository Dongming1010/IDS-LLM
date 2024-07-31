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
    if Std <= 9.8:
        dict['Std'] = Std
        threshholds.append(['Std', '<=', 9.8])
        if IAT <= 83033340.0:
            dict['IAT'] = IAT
            threshholds.append(['IAT', '<=', 83033340.0])
            if rst_count <= 0.5:
                dict['rst_count'] = rst_count
                threshholds.append(['rst_count', '<=', 0.5])
                if Magnitue <= 10.63:
                    dict['Magnitue'] = Magnitue
                    threshholds.append(['Magnitue', '<=', 10.63])
                    if Tot_size <= 56.38:
                        dict['Tot_size'] = Tot_size
                        threshholds.append(['Tot_size', '<=', 56.38])
                        if Number <= 9.28:
                            dict['Number'] = Number
                            threshholds.append(['Number', '<=', 9.28])
                            if IAT <= 0.02:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 0.02])
                                if AVG <= 55.42:
                                    dict['AVG'] = AVG
                                    threshholds.append(['AVG', '<=', 55.42])
                                    if Radius <= 5.87:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 5.87])
                                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if Radius > 5.87
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 5.87])
                                        return [[0. , 0. , 0. , 0. , 0. , 0.5, 0.5, 0. ]], dict, threshholds
                                else:  # if AVG > 55.42
                                    dict['AVG'] = AVG
                                    threshholds.append(['AVG', '>', 55.42])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if IAT > 0.02
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 0.02])
                                if Number <= 7.01:
                                    dict['Number'] = Number
                                    threshholds.append(['Number', '<=', 7.01])
                                    if Tot_sum <= 303.1:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 303.1])
                                        return [[0.   , 0.57142857, 0.   , 0.   , 0.   , 0.   ,  0.14285714, 0.28571429]], dict, threshholds
                                    else:  # if Tot_sum > 303.1
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 303.1])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Number > 7.01
                                    dict['Number'] = Number
                                    threshholds.append(['Number', '>', 7.01])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if Number > 9.28
                            dict['Number'] = Number
                            threshholds.append(['Number', '>', 9.28])
                            if Number <= 9.56:
                                dict['Number'] = Number
                                threshholds.append(['Number', '<=', 9.56])
                                return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Number > 9.56
                                dict['Number'] = Number
                                threshholds.append(['Number', '>', 9.56])
                                return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if Tot_size > 56.38
                        dict['Tot_size'] = Tot_size
                        threshholds.append(['Tot_size', '>', 56.38])
                        if IAT <= 41462904.01:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 41462904.01])
                            if IAT <= 0.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 0.0])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if IAT > 0.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 0.0])
                                if IAT <= 0.01:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 0.01])
                                    return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if IAT > 0.01
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 0.01])
                                    if Radius <= 8.31:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 8.31])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if Radius > 8.31
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 8.31])
                                        return [[0. , 0.5, 0. , 0. , 0. , 0. , 0. , 0.5]], dict, threshholds
                        else:  # if IAT > 41462904.01
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 41462904.01])
                            return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                else:  # if Magnitue > 10.63
                    dict['Magnitue'] = Magnitue
                    threshholds.append(['Magnitue', '>', 10.63])
                    if syn_count <= 0.29:
                        dict['syn_count'] = syn_count
                        threshholds.append(['syn_count', '<=', 0.29])
                        if flow_duration <= 0.39:
                            dict['flow_duration'] = flow_duration
                            threshholds.append(['flow_duration', '<=', 0.39])
                            if AVG <= 380.76:
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '<=', 380.76])
                                if Weight <= 77.83:
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '<=', 77.83])
                                    if AVG <= 59.13:
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '<=', 59.13])
                                        return [[0. , 0.5, 0. , 0. , 0. , 0. , 0. , 0.5]], dict, threshholds
                                    else:  # if AVG > 59.13
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '>', 59.13])
                                        return [[0.   , 0.07692308, 0.   , 0.   , 0.   , 0.   ,  0.92307692, 0.   ]], dict, threshholds
                                else:  # if Weight > 77.83
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '>', 77.83])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if AVG > 380.76
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '>', 380.76])
                                if Duration <= 61.5:
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '<=', 61.5])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if Duration > 61.5
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '>', 61.5])
                                    return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                        else:  # if flow_duration > 0.39
                            dict['flow_duration'] = flow_duration
                            threshholds.append(['flow_duration', '>', 0.39])
                            if TCP <= 0.5:
                                dict['TCP'] = TCP
                                threshholds.append(['TCP', '<=', 0.5])
                                if Number <= 6.0:
                                    dict['Number'] = Number
                                    threshholds.append(['Number', '<=', 6.0])
                                    if Tot_sum <= 354.75:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 354.75])
                                        return [[0.16666667, 0.66666667, 0.   , 0.   , 0.   , 0.   ,  0.16666667, 0.   ]], dict, threshholds
                                    else:  # if Tot_sum > 354.75
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 354.75])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.02173913, 0.01086957,  0.86956522, 0.09782609]], dict, threshholds
                                else:  # if Number > 6.0
                                    dict['Number'] = Number
                                    threshholds.append(['Number', '>', 6.0])
                                    if Srate <= 695.91:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 695.91])
                                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if Srate > 695.91
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 695.91])
                                        return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                            else:  # if TCP > 0.5
                                dict['TCP'] = TCP
                                threshholds.append(['TCP', '>', 0.5])
                                return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if syn_count > 0.29
                        dict['syn_count'] = syn_count
                        threshholds.append(['syn_count', '>', 0.29])
                        if IAT <= 0.01:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 0.01])
                            if Covariance <= 90.4:
                                dict['Covariance'] = Covariance
                                threshholds.append(['Covariance', '<=', 90.4])
                                if flow_duration <= 38.82:
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '<=', 38.82])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if flow_duration > 38.82
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '>', 38.82])
                                    if UDP <= 0.5:
                                        dict['UDP'] = UDP
                                        threshholds.append(['UDP', '<=', 0.5])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if UDP > 0.5
                                        dict['UDP'] = UDP
                                        threshholds.append(['UDP', '>', 0.5])
                                        return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Covariance > 90.4
                                dict['Covariance'] = Covariance
                                threshholds.append(['Covariance', '>', 90.4])
                                if Covariance <= 97.33:
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '<=', 97.33])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if Covariance > 97.33
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '>', 97.33])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                        else:  # if IAT > 0.01
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 0.01])
                            if IAT <= 78690612.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 78690612.0])
                                if Weight <= 83.68:
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '<=', 83.68])
                                    if flow_duration <= 516.47:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 516.47])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if flow_duration > 516.47
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 516.47])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Weight > 83.68
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '>', 83.68])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if IAT > 78690612.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 78690612.0])
                                return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
            else:  # if rst_count > 0.5
                dict['rst_count'] = rst_count
                threshholds.append(['rst_count', '>', 0.5])
                if flow_duration <= 0.15:
                    dict['flow_duration'] = flow_duration
                    threshholds.append(['flow_duration', '<=', 0.15])
                    if Weight <= 126.97:
                        dict['Weight'] = Weight
                        threshholds.append(['Weight', '<=', 126.97])
                        if Min <= 60.5:
                            dict['Min'] = Min
                            threshholds.append(['Min', '<=', 60.5])
                            if psh_flag_number <= 0.5:
                                dict['psh_flag_number'] = psh_flag_number
                                threshholds.append(['psh_flag_number', '<=', 0.5])
                                if Max <= 80.8:
                                    dict['Max'] = Max
                                    threshholds.append(['Max', '<=', 80.8])
                                    if rst_flag_number <= 0.5:
                                        dict['rst_flag_number'] = rst_flag_number
                                        threshholds.append(['rst_flag_number', '<=', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.99622642,  0.00377358, 0.   ]], dict, threshholds
                                    else:  # if rst_flag_number > 0.5
                                        dict['rst_flag_number'] = rst_flag_number
                                        threshholds.append(['rst_flag_number', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if Max > 80.8
                                    dict['Max'] = Max
                                    threshholds.append(['Max', '>', 80.8])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                            else:  # if psh_flag_number > 0.5
                                dict['psh_flag_number'] = psh_flag_number
                                threshholds.append(['psh_flag_number', '>', 0.5])
                                return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if Min > 60.5
                            dict['Min'] = Min
                            threshholds.append(['Min', '>', 60.5])
                            if SSH <= 0.5:
                                dict['SSH'] = SSH
                                threshholds.append(['SSH', '<=', 0.5])
                                if Covariance <= 1.12:
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '<=', 1.12])
                                    if Header_Length <= 27577.7:
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '<=', 27577.7])
                                        return [[0.05555556, 0.16666667, 0.   , 0.   , 0.   , 0.77777778,  0.   , 0.   ]], dict, threshholds
                                    else:  # if Header_Length > 27577.7
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '>', 27577.7])
                                        return [[0.18181818, 0.   , 0.   , 0.   , 0.   , 0.   ,  0.45454545, 0.36363636]], dict, threshholds
                                else:  # if Covariance > 1.12
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '>', 1.12])
                                    if HTTP <= 0.5:
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '<=', 0.5])
                                        return [[0.   , 0.78947368, 0.   , 0.   , 0.   , 0.10526316,  0.   , 0.10526316]], dict, threshholds
                                    else:  # if HTTP > 0.5
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '>', 0.5])
                                        return [[0.5, 0. , 0. , 0. , 0. , 0. , 0. , 0.5]], dict, threshholds
                            else:  # if SSH > 0.5
                                dict['SSH'] = SSH
                                threshholds.append(['SSH', '>', 0.5])
                                return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if Weight > 126.97
                        dict['Weight'] = Weight
                        threshholds.append(['Weight', '>', 126.97])
                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                else:  # if flow_duration > 0.15
                    dict['flow_duration'] = flow_duration
                    threshholds.append(['flow_duration', '>', 0.15])
                    if rst_count <= 287.0:
                        dict['rst_count'] = rst_count
                        threshholds.append(['rst_count', '<=', 287.0])
                        if Srate <= 6.95:
                            dict['Srate'] = Srate
                            threshholds.append(['Srate', '<=', 6.95])
                            if flow_duration <= 20.54:
                                dict['flow_duration'] = flow_duration
                                threshholds.append(['flow_duration', '<=', 20.54])
                                if Tot_sum <= 442.75:
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '<=', 442.75])
                                    if Tot_size <= 66.45:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 66.45])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if Tot_size > 66.45
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 66.45])
                                        return [[0.   , 0.8  , 0.   , 0.   , 0.   , 0.06666667,  0.13333333, 0.   ]], dict, threshholds
                                else:  # if Tot_sum > 442.75
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '>', 442.75])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if flow_duration > 20.54
                                dict['flow_duration'] = flow_duration
                                threshholds.append(['flow_duration', '>', 20.54])
                                if Min <= 67.7:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 67.7])
                                    if Srate <= 1.34:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 1.34])
                                        return [[0.05555556, 0.11111111, 0.   , 0.05555556, 0.   , 0.44444444,  0.11111111, 0.22222222]], dict, threshholds
                                    else:  # if Srate > 1.34
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 1.34])
                                        return [[0.12765957, 0.57446809, 0.   , 0.   , 0.   , 0.12765957,  0.12765957, 0.04255319]], dict, threshholds
                                else:  # if Min > 67.7
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 67.7])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                        else:  # if Srate > 6.95
                            dict['Srate'] = Srate
                            threshholds.append(['Srate', '>', 6.95])
                            if HTTPS <= 0.5:
                                dict['HTTPS'] = HTTPS
                                threshholds.append(['HTTPS', '<=', 0.5])
                                if IAT <= 41462536.02:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 41462536.02])
                                    if Magnitue <= 11.04:
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '<=', 11.04])
                                        return [[0.04347826, 0.04347826, 0.   , 0.   , 0.   , 0.83478261,  0.02608696, 0.05217391]], dict, threshholds
                                    else:  # if Magnitue > 11.04
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '>', 11.04])
                                        return [[0.03370787, 0.40449438, 0.   , 0.   , 0.   , 0.19101124,  0.07865169, 0.29213483]], dict, threshholds
                                else:  # if IAT > 41462536.02
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 41462536.02])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if HTTPS > 0.5
                                dict['HTTPS'] = HTTPS
                                threshholds.append(['HTTPS', '>', 0.5])
                                if Min <= 786.0:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 786.0])
                                    if rst_count <= 115.55:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 115.55])
                                        return [[0.10434783, 0.23478261, 0.   , 0.   , 0.   , 0.25217391,  0.16521739, 0.24347826]], dict, threshholds
                                    else:  # if rst_count > 115.55
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 115.55])
                                        return [[0.16483516, 0.10989011, 0.   , 0.   , 0.   , 0.13186813,  0.21978022, 0.37362637]], dict, threshholds
                                else:  # if Min > 786.0
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 786.0])
                                    if Rate <= 106.78:
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '<=', 106.78])
                                        return [[0.06896552, 0.10344828, 0.   , 0.   , 0.   , 0.06896552,  0.03448276, 0.72413793]], dict, threshholds
                                    else:  # if Rate > 106.78
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '>', 106.78])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                    else:  # if rst_count > 287.0
                        dict['rst_count'] = rst_count
                        threshholds.append(['rst_count', '>', 287.0])
                        if syn_count <= 0.7:
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '<=', 0.7])
                            if Rate <= 114.73:
                                dict['Rate'] = Rate
                                threshholds.append(['Rate', '<=', 114.73])
                                if urg_count <= 340.9:
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '<=', 340.9])
                                    if HTTP <= 0.5:
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '<=', 0.5])
                                        return [[0.75454545, 0.   , 0.   , 0.   , 0.   , 0.06363636,  0.09090909, 0.09090909]], dict, threshholds
                                    else:  # if HTTP > 0.5
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if urg_count > 340.9
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '>', 340.9])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if Rate > 114.73
                                dict['Rate'] = Rate
                                threshholds.append(['Rate', '>', 114.73])
                                if Min <= 1504.0:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 1504.0])
                                    if HTTP <= 0.5:
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '<=', 0.5])
                                        return [[0.03686636, 0.   , 0.   , 0.   , 0.   , 0.01843318,  0.94470046, 0.   ]], dict, threshholds
                                    else:  # if HTTP > 0.5
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '>', 0.5])
                                        return [[0.53846154, 0.   , 0.   , 0.   , 0.   , 0.   ,  0.46153846, 0.   ]], dict, threshholds
                                else:  # if Min > 1504.0
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 1504.0])
                                    if Duration <= 57.0:
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '<=', 57.0])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if Duration > 57.0
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '>', 57.0])
                                        return [[0.04, 0.  , 0.  , 0.  , 0.  , 0.04, 0.92, 0.  ]], dict, threshholds
                        else:  # if syn_count > 0.7
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '>', 0.7])
                            if IAT <= 0.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 0.0])
                                if Magnitue <= 53.6:
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '<=', 53.6])
                                    if HTTPS <= 0.5:
                                        dict['HTTPS'] = HTTPS
                                        threshholds.append(['HTTPS', '<=', 0.5])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if HTTPS > 0.5
                                        dict['HTTPS'] = HTTPS
                                        threshholds.append(['HTTPS', '>', 0.5])
                                        return [[0.32, 0.  , 0.  , 0.  , 0.  , 0.04, 0.48, 0.16]], dict, threshholds
                                else:  # if Magnitue > 53.6
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '>', 53.6])
                                    if Header_Length <= 427410.41:
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '<=', 427410.41])
                                        return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if Header_Length > 427410.41
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '>', 427410.41])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                            else:  # if IAT > 0.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 0.0])
                                if HTTPS <= 0.5:
                                    dict['HTTPS'] = HTTPS
                                    threshholds.append(['HTTPS', '<=', 0.5])
                                    if flow_duration <= 17.93:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 17.93])
                                        return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                    else:  # if flow_duration > 17.93
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 17.93])
                                        return [[0.28571429, 0.14285714, 0.   , 0.   , 0.   , 0.28571429,  0.   , 0.28571429]], dict, threshholds
                                else:  # if HTTPS > 0.5
                                    dict['HTTPS'] = HTTPS
                                    threshholds.append(['HTTPS', '>', 0.5])
                                    if AVG <= 60.58:
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '<=', 60.58])
                                        return [[0.25 , 0.125, 0.   , 0.   , 0.   , 0.   , 0.125, 0.5  ]], dict, threshholds
                                    else:  # if AVG > 60.58
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '>', 60.58])
                                        return [[0.78172589, 0.05583756, 0.   , 0.   , 0.   , 0.08629442,  0.07614213, 0.   ]], dict, threshholds
        else:  # if IAT > 83033340.0
            dict['IAT'] = IAT
            threshholds.append(['IAT', '>', 83033340.0])
            if fin_count <= 0.0:
                dict['fin_count'] = fin_count
                threshholds.append(['fin_count', '<=', 0.0])
                if TCP <= 0.5:
                    dict['TCP'] = TCP
                    threshholds.append(['TCP', '<=', 0.5])
                    if ack_count <= 0.02:
                        dict['ack_count'] = ack_count
                        threshholds.append(['ack_count', '<=', 0.02])
                        if Tot_size <= 292.18:
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '<=', 292.18])
                            if Radius <= 5.41:
                                dict['Radius'] = Radius
                                threshholds.append(['Radius', '<=', 5.41])
                                if Tot_sum <= 700.96:
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '<=', 700.96])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Tot_sum > 700.96
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '>', 700.96])
                                    if Magnitue <= 10.68:
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '<=', 10.68])
                                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if Magnitue > 10.68
                                        dict['Magnitue'] = Magnitue
                                        threshholds.append(['Magnitue', '>', 10.68])
                                        return [[0.    , 0.    , 0.    , 0.    , 0.    , 0.0625, 0.9375, 0.    ]], dict, threshholds
                            else:  # if Radius > 5.41
                                dict['Radius'] = Radius
                                threshholds.append(['Radius', '>', 5.41])
                                if Magnitue <= 10.39:
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '<=', 10.39])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Magnitue > 10.39
                                    dict['Magnitue'] = Magnitue
                                    threshholds.append(['Magnitue', '>', 10.39])
                                    if Max <= 74.7:
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '<=', 74.7])
                                        return [[0.16666667, 0.41666667, 0.   , 0.   , 0.   , 0.   ,  0.25 , 0.16666667]], dict, threshholds
                                    else:  # if Max > 74.7
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '>', 74.7])
                                        return [[0.   , 0.   , 0.11111111, 0.   , 0.   , 0.   ,  0.88888889, 0.   ]], dict, threshholds
                        else:  # if Tot_size > 292.18
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '>', 292.18])
                            if Tot_size <= 902.01:
                                dict['Tot_size'] = Tot_size
                                threshholds.append(['Tot_size', '<=', 902.01])
                                return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                            else:  # if Tot_size > 902.01
                                dict['Tot_size'] = Tot_size
                                threshholds.append(['Tot_size', '>', 902.01])
                                if Duration <= 54.0:
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '<=', 54.0])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                                else:  # if Duration > 54.0
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '>', 54.0])
                                    if IAT <= 166849664.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166849664.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.77777778, 0.22222222]], dict, threshholds
                                    else:  # if IAT > 166849664.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166849664.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                    else:  # if ack_count > 0.02
                        dict['ack_count'] = ack_count
                        threshholds.append(['ack_count', '>', 0.02])
                        if Variance <= 0.64:
                            dict['Variance'] = Variance
                            threshholds.append(['Variance', '<=', 0.64])
                            if Min <= 290.12:
                                dict['Min'] = Min
                                threshholds.append(['Min', '<=', 290.12])
                                return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Min > 290.12
                                dict['Min'] = Min
                                threshholds.append(['Min', '>', 290.12])
                                return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                        else:  # if Variance > 0.64
                            dict['Variance'] = Variance
                            threshholds.append(['Variance', '>', 0.64])
                            return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                else:  # if TCP > 0.5
                    dict['TCP'] = TCP
                    threshholds.append(['TCP', '>', 0.5])
                    if Number <= 11.5:
                        dict['Number'] = Number
                        threshholds.append(['Number', '<=', 11.5])
                        if Number <= 7.5:
                            dict['Number'] = Number
                            threshholds.append(['Number', '<=', 7.5])
                            if HTTPS <= 0.5:
                                dict['HTTPS'] = HTTPS
                                threshholds.append(['HTTPS', '<=', 0.5])
                                return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                            else:  # if HTTPS > 0.5
                                dict['HTTPS'] = HTTPS
                                threshholds.append(['HTTPS', '>', 0.5])
                                return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                        else:  # if Number > 7.5
                            dict['Number'] = Number
                            threshholds.append(['Number', '>', 7.5])
                            return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if Number > 11.5
                        dict['Number'] = Number
                        threshholds.append(['Number', '>', 11.5])
                        if Std <= 0.38:
                            dict['Std'] = Std
                            threshholds.append(['Std', '<=', 0.38])
                            if ack_flag_number <= 0.5:
                                dict['ack_flag_number'] = ack_flag_number
                                threshholds.append(['ack_flag_number', '<=', 0.5])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if ack_flag_number > 0.5
                                dict['ack_flag_number'] = ack_flag_number
                                threshholds.append(['ack_flag_number', '>', 0.5])
                                if IAT <= 166729200.0:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 166729200.0])
                                    if IAT <= 166602848.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166602848.0])
                                        return [[0.59459459, 0.05405405, 0.   , 0.   , 0.   , 0.35135135,  0.   , 0.   ]], dict, threshholds
                                    else:  # if IAT > 166602848.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166602848.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if IAT > 166729200.0
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 166729200.0])
                                    if AVG <= 66.04:
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '<=', 66.04])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.11627907,  0.23255814, 0.65116279]], dict, threshholds
                                    else:  # if AVG > 66.04
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '>', 66.04])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.02020202, 0.97979798]], dict, threshholds
                        else:  # if Std > 0.38
                            dict['Std'] = Std
                            threshholds.append(['Std', '>', 0.38])
                            if Magnitue <= 11.12:
                                dict['Magnitue'] = Magnitue
                                threshholds.append(['Magnitue', '<=', 11.12])
                                if syn_flag_number <= 0.5:
                                    dict['syn_flag_number'] = syn_flag_number
                                    threshholds.append(['syn_flag_number', '<=', 0.5])
                                    if IAT <= 166605808.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166605808.0])
                                        return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if IAT > 166605808.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166605808.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if syn_flag_number > 0.5
                                    dict['syn_flag_number'] = syn_flag_number
                                    threshholds.append(['syn_flag_number', '>', 0.5])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if Magnitue > 11.12
                                dict['Magnitue'] = Magnitue
                                threshholds.append(['Magnitue', '>', 11.12])
                                if Duration <= 100.6:
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '<=', 100.6])
                                    if syn_count <= 0.1:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 0.1])
                                        return [[0.05, 0.  , 0.  , 0.  , 0.  , 0.  , 0.9 , 0.05]], dict, threshholds
                                    else:  # if syn_count > 0.1
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 0.1])
                                        return [[0.   , 0.56097561, 0.   , 0.   , 0.   , 0.14634146,  0.09756098, 0.19512195]], dict, threshholds
                                else:  # if Duration > 100.6
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '>', 100.6])
                                    if Max <= 90.5:
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '<=', 90.5])
                                        return [[0.69565217, 0.   , 0.   , 0.   , 0.   , 0.04347826,  0.26086957, 0.   ]], dict, threshholds
                                    else:  # if Max > 90.5
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '>', 90.5])
                                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
            else:  # if fin_count > 0.0
                dict['fin_count'] = fin_count
                threshholds.append(['fin_count', '>', 0.0])
                if Weight <= 193.08:
                    dict['Weight'] = Weight
                    threshholds.append(['Weight', '<=', 193.08])
                    if fin_count <= 0.47:
                        dict['fin_count'] = fin_count
                        threshholds.append(['fin_count', '<=', 0.47])
                        if Max <= 64.31:
                            dict['Max'] = Max
                            threshholds.append(['Max', '<=', 64.31])
                            if AVG <= 56.22:
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '<=', 56.22])
                                return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if AVG > 56.22
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '>', 56.22])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                        else:  # if Max > 64.31
                            dict['Max'] = Max
                            threshholds.append(['Max', '>', 64.31])
                            if Max <= 364.0:
                                dict['Max'] = Max
                                threshholds.append(['Max', '<=', 364.0])
                                if fin_count <= 0.32:
                                    dict['fin_count'] = fin_count
                                    threshholds.append(['fin_count', '<=', 0.32])
                                    if IAT <= 83165664.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 83165664.0])
                                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if IAT > 83165664.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 83165664.0])
                                        return [[0. , 0. , 0.5, 0. , 0. , 0.5, 0. , 0. ]], dict, threshholds
                                else:  # if fin_count > 0.32
                                    dict['fin_count'] = fin_count
                                    threshholds.append(['fin_count', '>', 0.32])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if Max > 364.0
                                dict['Max'] = Max
                                threshholds.append(['Max', '>', 364.0])
                                return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                    else:  # if fin_count > 0.47
                        dict['fin_count'] = fin_count
                        threshholds.append(['fin_count', '>', 0.47])
                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                else:  # if Weight > 193.08
                    dict['Weight'] = Weight
                    threshholds.append(['Weight', '>', 193.08])
                    if Magnitue <= 11.14:
                        dict['Magnitue'] = Magnitue
                        threshholds.append(['Magnitue', '<=', 11.14])
                        if IAT <= 166850840.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 166850840.0])
                            if Max <= 54.2:
                                dict['Max'] = Max
                                threshholds.append(['Max', '<=', 54.2])
                                if AVG <= 53.88:
                                    dict['AVG'] = AVG
                                    threshholds.append(['AVG', '<=', 53.88])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if AVG > 53.88
                                    dict['AVG'] = AVG
                                    threshholds.append(['AVG', '>', 53.88])
                                    if Rate <= 7.23:
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '<=', 7.23])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.94117647,  0.05882353, 0.   ]], dict, threshholds
                                    else:  # if Rate > 7.23
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '>', 7.23])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if Max > 54.2
                                dict['Max'] = Max
                                threshholds.append(['Max', '>', 54.2])
                                return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                        else:  # if IAT > 166850840.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 166850840.0])
                            return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                    else:  # if Magnitue > 11.14
                        dict['Magnitue'] = Magnitue
                        threshholds.append(['Magnitue', '>', 11.14])
                        if Min <= 52.0:
                            dict['Min'] = Min
                            threshholds.append(['Min', '<=', 52.0])
                            return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if Min > 52.0
                            dict['Min'] = Min
                            threshholds.append(['Min', '>', 52.0])
                            return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
    else:  # if Std > 9.8
        dict['Std'] = Std
        threshholds.append(['Std', '>', 9.8])
        if IAT <= 166602848.0:
            dict['IAT'] = IAT
            threshholds.append(['IAT', '<=', 166602848.0])
            if Variance <= 0.39:
                dict['Variance'] = Variance
                threshholds.append(['Variance', '<=', 0.39])
                if IAT <= 83469472.0:
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '<=', 83469472.0])
                    if Header_Length <= 82721.44:
                        dict['Header_Length'] = Header_Length
                        threshholds.append(['Header_Length', '<=', 82721.44])
                        if Weight <= 140.4:
                            dict['Weight'] = Weight
                            threshholds.append(['Weight', '<=', 140.4])
                            if Protocol_Type <= 25.4:
                                dict['Protocol_Type'] = Protocol_Type
                                threshholds.append(['Protocol_Type', '<=', 25.4])
                                if HTTPS <= 0.5:
                                    dict['HTTPS'] = HTTPS
                                    threshholds.append(['HTTPS', '<=', 0.5])
                                    if SSH <= 0.5:
                                        dict['SSH'] = SSH
                                        threshholds.append(['SSH', '<=', 0.5])
                                        return [[0. , 0.1, 0. , 0. , 0. , 0.9, 0. , 0. ]], dict, threshholds
                                    else:  # if SSH > 0.5
                                        dict['SSH'] = SSH
                                        threshholds.append(['SSH', '>', 0.5])
                                        return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if HTTPS > 0.5
                                    dict['HTTPS'] = HTTPS
                                    threshholds.append(['HTTPS', '>', 0.5])
                                    if Rate <= 25.51:
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '<=', 25.51])
                                        return [[0.16666667, 0.16666667, 0.   , 0.   , 0.   , 0.   ,  0.   , 0.66666667]], dict, threshholds
                                    else:  # if Rate > 25.51
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '>', 25.51])
                                        return [[0.16, 0.24, 0.  , 0.  , 0.  , 0.08, 0.32, 0.2 ]], dict, threshholds
                            else:  # if Protocol_Type > 25.4
                                dict['Protocol_Type'] = Protocol_Type
                                threshholds.append(['Protocol_Type', '>', 25.4])
                                return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                        else:  # if Weight > 140.4
                            dict['Weight'] = Weight
                            threshholds.append(['Weight', '>', 140.4])
                            if Tot_sum <= 557.26:
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '<=', 557.26])
                                if Srate <= 107.41:
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '<=', 107.41])
                                    return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Srate > 107.41
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '>', 107.41])
                                    return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                            else:  # if Tot_sum > 557.26
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '>', 557.26])
                                if Rate <= 3.37:
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '<=', 3.37])
                                    if IAT <= 83022948.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 83022948.0])
                                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if IAT > 83022948.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 83022948.0])
                                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Rate > 3.37
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '>', 3.37])
                                    if ICMP <= 0.5:
                                        dict['ICMP'] = ICMP
                                        threshholds.append(['ICMP', '<=', 0.5])
                                        return [[0.   , 0.   , 0.20532319, 0.79087452, 0.   , 0.00380228,  0.   , 0.   ]], dict, threshholds
                                    else:  # if ICMP > 0.5
                                        dict['ICMP'] = ICMP
                                        threshholds.append(['ICMP', '>', 0.5])
                                        return [[0., 0., 1., 0., 0., 0., 0., 0.]], dict, threshholds
                    else:  # if Header_Length > 82721.44
                        dict['Header_Length'] = Header_Length
                        threshholds.append(['Header_Length', '>', 82721.44])
                        if urg_count <= 188.85:
                            dict['urg_count'] = urg_count
                            threshholds.append(['urg_count', '<=', 188.85])
                            if urg_count <= 14.65:
                                dict['urg_count'] = urg_count
                                threshholds.append(['urg_count', '<=', 14.65])
                                if Header_Length <= 180764.0:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 180764.0])
                                    if ack_flag_number <= 0.5:
                                        dict['ack_flag_number'] = ack_flag_number
                                        threshholds.append(['ack_flag_number', '<=', 0.5])
                                        return [[0., 0., 0., 1., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if ack_flag_number > 0.5
                                        dict['ack_flag_number'] = ack_flag_number
                                        threshholds.append(['ack_flag_number', '>', 0.5])
                                        return [[0.03125, 0.34375, 0.     , 0.     , 0.     , 0.     , 0.15625, 0.46875]], dict, threshholds
                                else:  # if Header_Length > 180764.0
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 180764.0])
                                    if Radius <= 48.07:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 48.07])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.44444444, 0.   ,  0.44444444, 0.11111111]], dict, threshholds
                                    else:  # if Radius > 48.07
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 48.07])
                                        return [[0.05555556, 0.   , 0.   , 0.02777778, 0.   , 0.   ,  0.66666667, 0.25 ]], dict, threshholds
                            else:  # if urg_count > 14.65
                                dict['urg_count'] = urg_count
                                threshholds.append(['urg_count', '>', 14.65])
                                if Tot_size <= 2347.6:
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '<=', 2347.6])
                                    if Header_Length <= 1000736.09:
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '<=', 1000736.09])
                                        return [[0.31034483, 0.10344828, 0.   , 0.   , 0.   , 0.20689655,  0.18965517, 0.18965517]], dict, threshholds
                                    else:  # if Header_Length > 1000736.09
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '>', 1000736.09])
                                        return [[0.87234043, 0.   , 0.   , 0.   , 0.   , 0.   ,  0.08510638, 0.04255319]], dict, threshholds
                                else:  # if Tot_size > 2347.6
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '>', 2347.6])
                                    if Covariance <= 915674.0:
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '<=', 915674.0])
                                        return [[0.2, 0. , 0. , 0. , 0. , 0. , 0. , 0.8]], dict, threshholds
                                    else:  # if Covariance > 915674.0
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '>', 915674.0])
                                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if urg_count > 188.85
                            dict['urg_count'] = urg_count
                            threshholds.append(['urg_count', '>', 188.85])
                            if HTTP <= 0.5:
                                dict['HTTP'] = HTTP
                                threshholds.append(['HTTP', '<=', 0.5])
                                if rst_count <= 6170.85:
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '<=', 6170.85])
                                    if Tot_sum <= 435.1:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 435.1])
                                        return [[0.5, 0. , 0. , 0. , 0. , 0. , 0.5, 0. ]], dict, threshholds
                                    else:  # if Tot_sum > 435.1
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 435.1])
                                        return [[0.025, 0.   , 0.   , 0.   , 0.   , 0.   , 0.925, 0.05 ]], dict, threshholds
                                else:  # if rst_count > 6170.85
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '>', 6170.85])
                                    if psh_flag_number <= 0.5:
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '<=', 0.5])
                                        return [[0.5, 0. , 0. , 0. , 0. , 0. , 0.5, 0. ]], dict, threshholds
                                    else:  # if psh_flag_number > 0.5
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if HTTP > 0.5
                                dict['HTTP'] = HTTP
                                threshholds.append(['HTTP', '>', 0.5])
                                return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                else:  # if IAT > 83469472.0
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '>', 83469472.0])
                    if IAT <= 133481500.0:
                        dict['IAT'] = IAT
                        threshholds.append(['IAT', '<=', 133481500.0])
                        return [[0., 0., 0., 0., 1., 0., 0., 0.]], dict, threshholds
                    else:  # if IAT > 133481500.0
                        dict['IAT'] = IAT
                        threshholds.append(['IAT', '>', 133481500.0])
                        if Tot_size <= 98.2:
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '<=', 98.2])
                            return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if Tot_size > 98.2
                            dict['Tot_size'] = Tot_size
                            threshholds.append(['Tot_size', '>', 98.2])
                            if syn_count <= 1.7:
                                dict['syn_count'] = syn_count
                                threshholds.append(['syn_count', '<=', 1.7])
                                if Rate <= 74.44:
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '<=', 74.44])
                                    return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Rate > 74.44
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '>', 74.44])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if syn_count > 1.7
                                dict['syn_count'] = syn_count
                                threshholds.append(['syn_count', '>', 1.7])
                                if Srate <= 73.62:
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '<=', 73.62])
                                    return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Srate > 73.62
                                    dict['Srate'] = Srate
                                    threshholds.append(['Srate', '>', 73.62])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
            else:  # if Variance > 0.39
                dict['Variance'] = Variance
                threshholds.append(['Variance', '>', 0.39])
                if HTTPS <= 0.5:
                    dict['HTTPS'] = HTTPS
                    threshholds.append(['HTTPS', '<=', 0.5])
                    if Number <= 12.75:
                        dict['Number'] = Number
                        threshholds.append(['Number', '<=', 12.75])
                        if Max <= 466.88:
                            dict['Max'] = Max
                            threshholds.append(['Max', '<=', 466.88])
                            if Number <= 7.5:
                                dict['Number'] = Number
                                threshholds.append(['Number', '<=', 7.5])
                                if Header_Length <= 150021.5:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 150021.5])
                                    if TCP <= 0.5:
                                        dict['TCP'] = TCP
                                        threshholds.append(['TCP', '<=', 0.5])
                                        return [[0.10306083, 0.25261527, 0.   , 0.   , 0.   , 0.1483921 ,  0.11390934, 0.38202247]], dict, threshholds
                                    else:  # if TCP > 0.5
                                        dict['TCP'] = TCP
                                        threshholds.append(['TCP', '>', 0.5])
                                        return [[0.08537693, 0.35603996, 0.   , 0.   , 0.   , 0.25158946,  0.06176203, 0.24523161]], dict, threshholds
                                else:  # if Header_Length > 150021.5
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 150021.5])
                                    if Protocol_Type <= 12.65:
                                        dict['Protocol_Type'] = Protocol_Type
                                        threshholds.append(['Protocol_Type', '<=', 12.65])
                                        return [[0.59776536, 0.02234637, 0.   , 0.   , 0.   , 0.08938547,  0.20670391, 0.08379888]], dict, threshholds
                                    else:  # if Protocol_Type > 12.65
                                        dict['Protocol_Type'] = Protocol_Type
                                        threshholds.append(['Protocol_Type', '>', 12.65])
                                        return [[0.05555556, 0.   , 0.   , 0.   , 0.   , 0.00617284,  0.92592593, 0.01234568]], dict, threshholds
                            else:  # if Number > 7.5
                                dict['Number'] = Number
                                threshholds.append(['Number', '>', 7.5])
                                if HTTP <= 0.5:
                                    dict['HTTP'] = HTTP
                                    threshholds.append(['HTTP', '<=', 0.5])
                                    if rst_count <= 1.32:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 1.32])
                                        return [[0.   , 0.   , 0.25 , 0.58333333, 0.05555556, 0.11111111,  0.   , 0.   ]], dict, threshholds
                                    else:  # if rst_count > 1.32
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 1.32])
                                        return [[0.   , 0.   , 0.00797872, 0.03191489, 0.02659574, 0.93351064,  0.   , 0.   ]], dict, threshholds
                                else:  # if HTTP > 0.5
                                    dict['HTTP'] = HTTP
                                    threshholds.append(['HTTP', '>', 0.5])
                                    if flow_duration <= 0.59:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 0.59])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if flow_duration > 0.59
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 0.59])
                                        return [[0. , 0. , 0.5, 0.5, 0. , 0. , 0. , 0. ]], dict, threshholds
                        else:  # if Max > 466.88
                            dict['Max'] = Max
                            threshholds.append(['Max', '>', 466.88])
                            if Weight <= 79.94:
                                dict['Weight'] = Weight
                                threshholds.append(['Weight', '<=', 79.94])
                                if UDP <= 0.5:
                                    dict['UDP'] = UDP
                                    threshholds.append(['UDP', '<=', 0.5])
                                    if Radius <= 753.63:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 753.63])
                                        return [[0.11621622, 0.38513514, 0.00135135, 0.   , 0.   , 0.07162162,  0.13108108, 0.29459459]], dict, threshholds
                                    else:  # if Radius > 753.63
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 753.63])
                                        return [[0.32535885, 0.03110048, 0.   , 0.   , 0.   , 0.11722488,  0.38995215, 0.13636364]], dict, threshholds
                                else:  # if UDP > 0.5
                                    dict['UDP'] = UDP
                                    threshholds.append(['UDP', '>', 0.5])
                                    if Srate <= 29.92:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 29.92])
                                        return [[0.14516129, 0.09677419, 0.   , 0.   , 0.   , 0.22580645,  0.37096774, 0.16129032]], dict, threshholds
                                    else:  # if Srate > 29.92
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 29.92])
                                        return [[0.0195122 , 0.00731707, 0.   , 0.   , 0.   , 0.01219512,  0.9195122 , 0.04146341]], dict, threshholds
                            else:  # if Weight > 79.94
                                dict['Weight'] = Weight
                                threshholds.append(['Weight', '>', 79.94])
                                if Variance <= 0.83:
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '<=', 0.83])
                                    if rst_count <= 5.44:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 5.44])
                                        return [[0.   , 0.   , 0.01421801, 0.02843602, 0.95260664, 0.00473934,  0.   , 0.   ]], dict, threshholds
                                    else:  # if rst_count > 5.44
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 5.44])
                                        return [[0.   , 0.   , 0.02631579, 0.60526316, 0.23684211, 0.13157895,  0.   , 0.   ]], dict, threshholds
                                else:  # if Variance > 0.83
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '>', 0.83])
                                    if Tot_size <= 478.82:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 478.82])
                                        return [[0.   , 0.   , 0.0199005 , 0.04477612, 0.06467662, 0.86567164,  0.   , 0.00497512]], dict, threshholds
                                    else:  # if Tot_size > 478.82
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 478.82])
                                        return [[0.   , 0.   , 0.74770642, 0.0733945 , 0.01834862, 0.16055046,  0.   , 0.   ]], dict, threshholds
                    else:  # if Number > 12.75
                        dict['Number'] = Number
                        threshholds.append(['Number', '>', 12.75])
                        if IAT <= 166551400.0:
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '<=', 166551400.0])
                            if IAT <= 166499176.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 166499176.0])
                                if Tot_size <= 85.75:
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '<=', 85.75])
                                    if syn_count <= 0.45:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 0.45])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.55371901,  0.   , 0.44628099]], dict, threshholds
                                    else:  # if syn_count > 0.45
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 0.45])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.86982249,  0.   , 0.13017751]], dict, threshholds
                                else:  # if Tot_size > 85.75
                                    dict['Tot_size'] = Tot_size
                                    threshholds.append(['Tot_size', '>', 85.75])
                                    if Tot_sum <= 3884.2:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 3884.2])
                                        return [[0.001221  , 0.001221  , 0.   , 0.   , 0.   , 0.51526252,  0.   , 0.48229548]], dict, threshholds
                                    else:  # if Tot_sum > 3884.2
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 3884.2])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.84, 0.  , 0.16]], dict, threshholds
                            else:  # if IAT > 166499176.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 166499176.0])
                                return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                        else:  # if IAT > 166551400.0
                            dict['IAT'] = IAT
                            threshholds.append(['IAT', '>', 166551400.0])
                            return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                else:  # if HTTPS > 0.5
                    dict['HTTPS'] = HTTPS
                    threshholds.append(['HTTPS', '>', 0.5])
                    if Rate <= 292.85:
                        dict['Rate'] = Rate
                        threshholds.append(['Rate', '<=', 292.85])
                        if rst_count <= 284.45:
                            dict['rst_count'] = rst_count
                            threshholds.append(['rst_count', '<=', 284.45])
                            if Max <= 873.25:
                                dict['Max'] = Max
                                threshholds.append(['Max', '<=', 873.25])
                                if ack_count <= 0.13:
                                    dict['ack_count'] = ack_count
                                    threshholds.append(['ack_count', '<=', 0.13])
                                    if fin_count <= 0.08:
                                        dict['fin_count'] = fin_count
                                        threshholds.append(['fin_count', '<=', 0.08])
                                        return [[0.16735113, 0.30595483, 0.   , 0.00308008, 0.   , 0.137577  ,  0.11601643, 0.27002053]], dict, threshholds
                                    else:  # if fin_count > 0.08
                                        dict['fin_count'] = fin_count
                                        threshholds.append(['fin_count', '>', 0.08])
                                        return [[0.03636364, 0.54545455, 0.   , 0.   , 0.   , 0.18181818,  0.14545455, 0.09090909]], dict, threshholds
                                else:  # if ack_count > 0.13
                                    dict['ack_count'] = ack_count
                                    threshholds.append(['ack_count', '>', 0.13])
                                    if Max <= 140.5:
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '<=', 140.5])
                                        return [[0.1 , 0.36, 0.  , 0.  , 0.  , 0.26, 0.16, 0.12]], dict, threshholds
                                    else:  # if Max > 140.5
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '>', 140.5])
                                        return [[0.16993464, 0.15686275, 0.00217865, 0.   , 0.   , 0.30501089,  0.05010893, 0.31590414]], dict, threshholds
                            else:  # if Max > 873.25
                                dict['Max'] = Max
                                threshholds.append(['Max', '>', 873.25])
                                if Variance <= 0.97:
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '<=', 0.97])
                                    if Header_Length <= 156572.95:
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '<=', 156572.95])
                                        return [[0.13608247, 0.36804124, 0.   , 0.00515464, 0.00515464, 0.13092784,  0.12989691, 0.22474227]], dict, threshholds
                                    else:  # if Header_Length > 156572.95
                                        dict['Header_Length'] = Header_Length
                                        threshholds.append(['Header_Length', '>', 156572.95])
                                        return [[0.49717514, 0.06779661, 0.   , 0.   , 0.00564972, 0.11864407,  0.23728814, 0.07344633]], dict, threshholds
                                else:  # if Variance > 0.97
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '>', 0.97])
                                    if syn_count <= 0.65:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 0.65])
                                        return [[0.64754098, 0.17213115, 0.   , 0.   , 0.   , 0.13934426,  0.   , 0.04098361]], dict, threshholds
                                    else:  # if syn_count > 0.65
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 0.65])
                                        return [[0.25775656, 0.55250597, 0.   , 0.   , 0.   , 0.13365155,  0.   , 0.05608592]], dict, threshholds
                        else:  # if rst_count > 284.45
                            dict['rst_count'] = rst_count
                            threshholds.append(['rst_count', '>', 284.45])
                            if Covariance <= 19281.41:
                                dict['Covariance'] = Covariance
                                threshholds.append(['Covariance', '<=', 19281.41])
                                if Header_Length <= 220049.1:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 220049.1])
                                    if IAT <= 166551376.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166551376.0])
                                        return [[0.33647059, 0.28470588, 0.   , 0.   , 0.   , 0.24941176,  0.04 , 0.08941176]], dict, threshholds
                                    else:  # if IAT > 166551376.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166551376.0])
                                        return [[0., 1., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                else:  # if Header_Length > 220049.1
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 220049.1])
                                    if IAT <= 166473832.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166473832.0])
                                        return [[0.72875817, 0.05228758, 0.   , 0.   , 0.   , 0.12418301,  0.09477124, 0.   ]], dict, threshholds
                                    else:  # if IAT > 166473832.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166473832.0])
                                        return [[0.98461538, 0.01538462, 0.   , 0.   , 0.   , 0.   ,  0.   , 0.   ]], dict, threshholds
                            else:  # if Covariance > 19281.41
                                dict['Covariance'] = Covariance
                                threshholds.append(['Covariance', '>', 19281.41])
                                if Min <= 67.95:
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '<=', 67.95])
                                    if Weight <= 193.08:
                                        dict['Weight'] = Weight
                                        threshholds.append(['Weight', '<=', 193.08])
                                        return [[0.62383613, 0.0707635 , 0.   , 0.   , 0.   , 0.11731844,  0.17318436, 0.01489758]], dict, threshholds
                                    else:  # if Weight > 193.08
                                        dict['Weight'] = Weight
                                        threshholds.append(['Weight', '>', 193.08])
                                        return [[0.81155433, 0.08046768, 0.   , 0.   , 0.   , 0.10660248,  0.   , 0.00137552]], dict, threshholds
                                else:  # if Min > 67.95
                                    dict['Min'] = Min
                                    threshholds.append(['Min', '>', 67.95])
                                    if psh_flag_number <= 0.5:
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '<=', 0.5])
                                        return [[0.70740741, 0.06111111, 0.   , 0.00185185, 0.   , 0.09444444,  0.1287037 , 0.00648148]], dict, threshholds
                                    else:  # if psh_flag_number > 0.5
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '>', 0.5])
                                        return [[0.17460317, 0.03174603, 0.   , 0.   , 0.   , 0.06349206,  0.71428571, 0.01587302]], dict, threshholds
                    else:  # if Rate > 292.85
                        dict['Rate'] = Rate
                        threshholds.append(['Rate', '>', 292.85])
                        if syn_count <= 0.45:
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '<=', 0.45])
                            if AVG <= 1382.54:
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '<=', 1382.54])
                                if Variance <= 0.95:
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '<=', 0.95])
                                    if IAT <= 0.01:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 0.01])
                                        return [[0.04580153, 0.00763359, 0.   , 0.   , 0.   , 0.01526718,  0.90839695, 0.02290076]], dict, threshholds
                                    else:  # if IAT > 0.01
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 0.01])
                                        return [[0.35714286, 0.07142857, 0.   , 0.   , 0.14285714, 0.03571429,  0.25 , 0.14285714]], dict, threshholds
                                else:  # if Variance > 0.95
                                    dict['Variance'] = Variance
                                    threshholds.append(['Variance', '>', 0.95])
                                    if syn_count <= 0.25:
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '<=', 0.25])
                                        return [[0.68181818, 0.09090909, 0.   , 0.   , 0.   , 0.22727273,  0.   , 0.   ]], dict, threshholds
                                    else:  # if syn_count > 0.25
                                        dict['syn_count'] = syn_count
                                        threshholds.append(['syn_count', '>', 0.25])
                                        return [[0. , 0.5, 0. , 0. , 0. , 0. , 0. , 0.5]], dict, threshholds
                            else:  # if AVG > 1382.54
                                dict['AVG'] = AVG
                                threshholds.append(['AVG', '>', 1382.54])
                                if IAT <= 83219648.01:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 83219648.01])
                                    if urg_count <= 86.1:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 86.1])
                                        return [[0.03809524, 0.   , 0.   , 0.   , 0.   , 0.01904762,  0.85714286, 0.08571429]], dict, threshholds
                                    else:  # if urg_count > 86.1
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 86.1])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if IAT > 83219648.01
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 83219648.01])
                                    if rst_count <= 178.75:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 178.75])
                                        return [[1., 0., 0., 0., 0., 0., 0., 0.]], dict, threshholds
                                    else:  # if rst_count > 178.75
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 178.75])
                                        return [[0.75, 0.  , 0.  , 0.  , 0.  , 0.25, 0.  , 0.  ]], dict, threshholds
                        else:  # if syn_count > 0.45
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '>', 0.45])
                            if Max <= 3093.8:
                                dict['Max'] = Max
                                threshholds.append(['Max', '<=', 3093.8])
                                if Weight <= 90.03:
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '<=', 90.03])
                                    if rst_count <= 1266.6:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 1266.6])
                                        return [[0.18333333, 0.13333333, 0.   , 0.   , 0.   , 0.1  ,  0.26666667, 0.31666667]], dict, threshholds
                                    else:  # if rst_count > 1266.6
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 1266.6])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.  , 0.25, 0.75]], dict, threshholds
                                else:  # if Weight > 90.03
                                    dict['Weight'] = Weight
                                    threshholds.append(['Weight', '>', 90.03])
                                    if rst_count <= 89.1:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 89.1])
                                        return [[0.   , 0.33333333, 0.   , 0.   , 0.11111111, 0.44444444,  0.   , 0.11111111]], dict, threshholds
                                    else:  # if rst_count > 89.1
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 89.1])
                                        return [[0.61904762, 0.14285714, 0.04761905, 0.   , 0.   , 0.19047619,  0.   , 0.   ]], dict, threshholds
                            else:  # if Max > 3093.8
                                dict['Max'] = Max
                                threshholds.append(['Max', '>', 3093.8])
                                if Covariance <= 2317899.75:
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '<=', 2317899.75])
                                    if Number <= 9.5:
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '<=', 9.5])
                                        return [[0.   , 0.21428571, 0.   , 0.   , 0.   , 0.07142857,  0.67857143, 0.03571429]], dict, threshholds
                                    else:  # if Number > 9.5
                                        dict['Number'] = Number
                                        threshholds.append(['Number', '>', 9.5])
                                        return [[0.125, 0.75 , 0.   , 0.   , 0.   , 0.125, 0.   , 0.   ]], dict, threshholds
                                else:  # if Covariance > 2317899.75
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '>', 2317899.75])
                                    if Duration <= 62.75:
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '<=', 62.75])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.25, 0.75, 0.  ]], dict, threshholds
                                    else:  # if Duration > 62.75
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '>', 62.75])
                                        return [[0.5, 0.1, 0. , 0. , 0. , 0. , 0.2, 0.2]], dict, threshholds
        else:  # if IAT > 166602848.0
            dict['IAT'] = IAT
            threshholds.append(['IAT', '>', 166602848.0])
            if Radius <= 278.51:
                dict['Radius'] = Radius
                threshholds.append(['Radius', '<=', 278.51])
                if IAT <= 167246344.0:
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '<=', 167246344.0])
                    if syn_count <= 0.05:
                        dict['syn_count'] = syn_count
                        threshholds.append(['syn_count', '<=', 0.05])
                        if Duration <= 84.4:
                            dict['Duration'] = Duration
                            threshholds.append(['Duration', '<=', 84.4])
                            if rst_count <= 4.3:
                                dict['rst_count'] = rst_count
                                threshholds.append(['rst_count', '<=', 4.3])
                                if Covariance <= 6269.43:
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '<=', 6269.43])
                                    if UDP <= 0.5:
                                        dict['UDP'] = UDP
                                        threshholds.append(['UDP', '<=', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.33333333,  0.58333333, 0.08333333]], dict, threshholds
                                    else:  # if UDP > 0.5
                                        dict['UDP'] = UDP
                                        threshholds.append(['UDP', '>', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.05454545,  0.90909091, 0.03636364]], dict, threshholds
                                else:  # if Covariance > 6269.43
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '>', 6269.43])
                                    if Rate <= 28.62:
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '<=', 28.62])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.89473684, 0.10526316]], dict, threshholds
                                    else:  # if Rate > 28.62
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '>', 28.62])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if rst_count > 4.3
                                dict['rst_count'] = rst_count
                                threshholds.append(['rst_count', '>', 4.3])
                                if Tot_sum <= 1616.65:
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '<=', 1616.65])
                                    if HTTP <= 0.5:
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '<=', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.08139535,  0.84883721, 0.06976744]], dict, threshholds
                                    else:  # if HTTP > 0.5
                                        dict['HTTP'] = HTTP
                                        threshholds.append(['HTTP', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Tot_sum > 1616.65
                                    dict['Tot_sum'] = Tot_sum
                                    threshholds.append(['Tot_sum', '>', 1616.65])
                                    if urg_count <= 64.35:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 64.35])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.15384615,  0.5  , 0.34615385]], dict, threshholds
                                    else:  # if urg_count > 64.35
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 64.35])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.125, 0.75 , 0.125]], dict, threshholds
                        else:  # if Duration > 84.4
                            dict['Duration'] = Duration
                            threshholds.append(['Duration', '>', 84.4])
                            if Header_Length <= 221395.0:
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '<=', 221395.0])
                                if rst_count <= 240.9:
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '<=', 240.9])
                                    if AVG <= 98.91:
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '<=', 98.91])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.2295082,  0.6557377, 0.1147541]], dict, threshholds
                                    else:  # if AVG > 98.91
                                        dict['AVG'] = AVG
                                        threshholds.append(['AVG', '>', 98.91])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.26180258,  0.41630901, 0.32188841]], dict, threshholds
                                else:  # if rst_count > 240.9
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '>', 240.9])
                                    if Covariance <= 4959.5:
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '<=', 4959.5])
                                        return [[0.   , 0.02325581, 0.   , 0.   , 0.   , 0.76744186,  0.20930233, 0.   ]], dict, threshholds
                                    else:  # if Covariance > 4959.5
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '>', 4959.5])
                                        return [[0. , 0. , 0. , 0. , 0. , 0.3, 0.6, 0.1]], dict, threshholds
                            else:  # if Header_Length > 221395.0
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '>', 221395.0])
                                if Radius <= 56.66:
                                    dict['Radius'] = Radius
                                    threshholds.append(['Radius', '<=', 56.66])
                                    if Srate <= 34.16:
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '<=', 34.16])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                    else:  # if Srate > 34.16
                                        dict['Srate'] = Srate
                                        threshholds.append(['Srate', '>', 34.16])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Radius > 56.66
                                    dict['Radius'] = Radius
                                    threshholds.append(['Radius', '>', 56.66])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                    else:  # if syn_count > 0.05
                        dict['syn_count'] = syn_count
                        threshholds.append(['syn_count', '>', 0.05])
                        if fin_count <= 0.05:
                            dict['fin_count'] = fin_count
                            threshholds.append(['fin_count', '<=', 0.05])
                            if Covariance <= 18379.3:
                                dict['Covariance'] = Covariance
                                threshholds.append(['Covariance', '<=', 18379.3])
                                if syn_count <= 0.15:
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '<=', 0.15])
                                    if flow_duration <= 72.36:
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '<=', 72.36])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.47058824,  0.47058824, 0.05882353]], dict, threshholds
                                    else:  # if flow_duration > 72.36
                                        dict['flow_duration'] = flow_duration
                                        threshholds.append(['flow_duration', '>', 72.36])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.85714286,  0.11428571, 0.02857143]], dict, threshholds
                                else:  # if syn_count > 0.15
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '>', 0.15])
                                    if Radius <= 69.8:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 69.8])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.24299065,  0.58878505, 0.1682243 ]], dict, threshholds
                                    else:  # if Radius > 69.8
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 69.8])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.42618384,  0.35933148, 0.21448468]], dict, threshholds
                            else:  # if Covariance > 18379.3
                                dict['Covariance'] = Covariance
                                threshholds.append(['Covariance', '>', 18379.3])
                                if IAT <= 166846232.0:
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '<=', 166846232.0])
                                    if Duration <= 160.4:
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '<=', 160.4])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.21495327, 0.78504673]], dict, threshholds
                                    else:  # if Duration > 160.4
                                        dict['Duration'] = Duration
                                        threshholds.append(['Duration', '>', 160.4])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.83333333, 0.16666667]], dict, threshholds
                                else:  # if IAT > 166846232.0
                                    dict['IAT'] = IAT
                                    threshholds.append(['IAT', '>', 166846232.0])
                                    if urg_count <= 36.65:
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '<=', 36.65])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.18518519,  0.81481481, 0.   ]], dict, threshholds
                                    else:  # if urg_count > 36.65
                                        dict['urg_count'] = urg_count
                                        threshholds.append(['urg_count', '>', 36.65])
                                        return [[0. , 0. , 0. , 0. , 0. , 0.5, 0.5, 0. ]], dict, threshholds
                        else:  # if fin_count > 0.05
                            dict['fin_count'] = fin_count
                            threshholds.append(['fin_count', '>', 0.05])
                            if Tot_sum <= 1398.8:
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '<=', 1398.8])
                                if syn_count <= 1.75:
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '<=', 1.75])
                                    if Protocol_Type <= 10.7:
                                        dict['Protocol_Type'] = Protocol_Type
                                        threshholds.append(['Protocol_Type', '<=', 10.7])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.98086124,  0.01913876, 0.   ]], dict, threshholds
                                    else:  # if Protocol_Type > 10.7
                                        dict['Protocol_Type'] = Protocol_Type
                                        threshholds.append(['Protocol_Type', '>', 10.7])
                                        return [[0. , 0. , 0. , 0. , 0. , 0.5, 0.5, 0. ]], dict, threshholds
                                else:  # if syn_count > 1.75
                                    dict['syn_count'] = syn_count
                                    threshholds.append(['syn_count', '>', 1.75])
                                    return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                            else:  # if Tot_sum > 1398.8
                                dict['Tot_sum'] = Tot_sum
                                threshholds.append(['Tot_sum', '>', 1398.8])
                                if Header_Length <= 23286.3:
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '<=', 23286.3])
                                    if Radius <= 81.55:
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '<=', 81.55])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.22222222,  0.77777778, 0.   ]], dict, threshholds
                                    else:  # if Radius > 81.55
                                        dict['Radius'] = Radius
                                        threshholds.append(['Radius', '>', 81.55])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.73469388,  0.18367347, 0.08163265]], dict, threshholds
                                else:  # if Header_Length > 23286.3
                                    dict['Header_Length'] = Header_Length
                                    threshholds.append(['Header_Length', '>', 23286.3])
                                    if IAT <= 166729120.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166729120.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if IAT > 166729120.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166729120.0])
                                        return [[0. , 0. , 0. , 0. , 0. , 0.2, 0.5, 0.3]], dict, threshholds
                else:  # if IAT > 167246344.0
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '>', 167246344.0])
                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
            else:  # if Radius > 278.51
                dict['Radius'] = Radius
                threshholds.append(['Radius', '>', 278.51])
                if IAT <= 167246344.0:
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '<=', 167246344.0])
                    if Srate <= 22.49:
                        dict['Srate'] = Srate
                        threshholds.append(['Srate', '<=', 22.49])
                        if AVG <= 203.92:
                            dict['AVG'] = AVG
                            threshholds.append(['AVG', '<=', 203.92])
                            if IAT <= 166850728.0:
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '<=', 166850728.0])
                                if Duration <= 116.55:
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '<=', 116.55])
                                    if psh_flag_number <= 0.5:
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '<=', 0.5])
                                        return [[0.    , 0.    , 0.    , 0.    , 0.    , 0.25  , 0.5625, 0.1875]], dict, threshholds
                                    else:  # if psh_flag_number > 0.5
                                        dict['psh_flag_number'] = psh_flag_number
                                        threshholds.append(['psh_flag_number', '>', 0.5])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                else:  # if Duration > 116.55
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '>', 116.55])
                                    return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                            else:  # if IAT > 166850728.0
                                dict['IAT'] = IAT
                                threshholds.append(['IAT', '>', 166850728.0])
                                return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                        else:  # if AVG > 203.92
                            dict['AVG'] = AVG
                            threshholds.append(['AVG', '>', 203.92])
                            if Header_Length <= 7715.2:
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '<=', 7715.2])
                                if rst_count <= 39.4:
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '<=', 39.4])
                                    if Covariance <= 86125.98:
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '<=', 86125.98])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.83333333, 0.16666667]], dict, threshholds
                                    else:  # if Covariance > 86125.98
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '>', 86125.98])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.51219512,  0.12195122, 0.36585366]], dict, threshholds
                                else:  # if rst_count > 39.4
                                    dict['rst_count'] = rst_count
                                    threshholds.append(['rst_count', '>', 39.4])
                                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds
                            else:  # if Header_Length > 7715.2
                                dict['Header_Length'] = Header_Length
                                threshholds.append(['Header_Length', '>', 7715.2])
                                if urg_count <= 12.1:
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '<=', 12.1])
                                    if Max <= 3076.5:
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '<=', 3076.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.04166667,  0.91666667, 0.04166667]], dict, threshholds
                                    else:  # if Max > 3076.5
                                        dict['Max'] = Max
                                        threshholds.append(['Max', '>', 3076.5])
                                        return [[0. , 0. , 0. , 0. , 0. , 0. , 0.5, 0.5]], dict, threshholds
                                else:  # if urg_count > 12.1
                                    dict['urg_count'] = urg_count
                                    threshholds.append(['urg_count', '>', 12.1])
                                    if Covariance <= 1051078.34:
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '<=', 1051078.34])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.09574468,  0.4893617 , 0.41489362]], dict, threshholds
                                    else:  # if Covariance > 1051078.34
                                        dict['Covariance'] = Covariance
                                        threshholds.append(['Covariance', '>', 1051078.34])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.19047619,  0.80952381, 0.   ]], dict, threshholds
                    else:  # if Srate > 22.49
                        dict['Srate'] = Srate
                        threshholds.append(['Srate', '>', 22.49])
                        if syn_count <= 1.55:
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '<=', 1.55])
                            if flow_duration <= 0.2:
                                dict['flow_duration'] = flow_duration
                                threshholds.append(['flow_duration', '<=', 0.2])
                                if Rate <= 1169.08:
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '<=', 1169.08])
                                    if fin_count <= 0.35:
                                        dict['fin_count'] = fin_count
                                        threshholds.append(['fin_count', '<=', 0.35])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.07317073,  0.53658537, 0.3902439 ]], dict, threshholds
                                    else:  # if fin_count > 0.35
                                        dict['fin_count'] = fin_count
                                        threshholds.append(['fin_count', '>', 0.35])
                                        return [[0., 0., 0., 0., 0., 1., 0., 0.]], dict, threshholds
                                else:  # if Rate > 1169.08
                                    dict['Rate'] = Rate
                                    threshholds.append(['Rate', '>', 1169.08])
                                    if Tot_sum <= 37934.4:
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '<=', 37934.4])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if Tot_sum > 37934.4
                                        dict['Tot_sum'] = Tot_sum
                                        threshholds.append(['Tot_sum', '>', 37934.4])
                                        return [[0.  , 0.  , 0.  , 0.  , 0.  , 0.  , 0.75, 0.25]], dict, threshholds
                            else:  # if flow_duration > 0.2
                                dict['flow_duration'] = flow_duration
                                threshholds.append(['flow_duration', '>', 0.2])
                                if Covariance <= 81486.11:
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '<=', 81486.11])
                                    if TCP <= 0.5:
                                        dict['TCP'] = TCP
                                        threshholds.append(['TCP', '<=', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.91176471, 0.08823529]], dict, threshholds
                                    else:  # if TCP > 0.5
                                        dict['TCP'] = TCP
                                        threshholds.append(['TCP', '>', 0.5])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.22222222,  0.38888889, 0.38888889]], dict, threshholds
                                else:  # if Covariance > 81486.11
                                    dict['Covariance'] = Covariance
                                    threshholds.append(['Covariance', '>', 81486.11])
                                    if Tot_size <= 350.8:
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '<=', 350.8])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.04057971,  0.90724638, 0.05217391]], dict, threshholds
                                    else:  # if Tot_size > 350.8
                                        dict['Tot_size'] = Tot_size
                                        threshholds.append(['Tot_size', '>', 350.8])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.00622222,  0.968     , 0.02577778]], dict, threshholds
                        else:  # if syn_count > 1.55
                            dict['syn_count'] = syn_count
                            threshholds.append(['syn_count', '>', 1.55])
                            if flow_duration <= 3.07:
                                dict['flow_duration'] = flow_duration
                                threshholds.append(['flow_duration', '<=', 3.07])
                                if Duration <= 246.5:
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '<=', 246.5])
                                    if IAT <= 166729192.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166729192.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if IAT > 166729192.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166729192.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.12565445,  0.20418848, 0.67015707]], dict, threshholds
                                else:  # if Duration > 246.5
                                    dict['Duration'] = Duration
                                    threshholds.append(['Duration', '>', 246.5])
                                    if IAT <= 166729152.0:
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '<=', 166729152.0])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if IAT > 166729152.0
                                        dict['IAT'] = IAT
                                        threshholds.append(['IAT', '>', 166729152.0])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.875, 0.125, 0.   ]], dict, threshholds
                            else:  # if flow_duration > 3.07
                                dict['flow_duration'] = flow_duration
                                threshholds.append(['flow_duration', '>', 3.07])
                                if flow_duration <= 3.52:
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '<=', 3.52])
                                    if Rate <= 372.16:
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '<=', 372.16])
                                        return [[0., 0., 0., 0., 0., 0., 1., 0.]], dict, threshholds
                                    else:  # if Rate > 372.16
                                        dict['Rate'] = Rate
                                        threshholds.append(['Rate', '>', 372.16])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.   ,  0.66666667, 0.33333333]], dict, threshholds
                                else:  # if flow_duration > 3.52
                                    dict['flow_duration'] = flow_duration
                                    threshholds.append(['flow_duration', '>', 3.52])
                                    if rst_count <= 732.1:
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '<=', 732.1])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.11538462,  0.71153846, 0.17307692]], dict, threshholds
                                    else:  # if rst_count > 732.1
                                        dict['rst_count'] = rst_count
                                        threshholds.append(['rst_count', '>', 732.1])
                                        return [[0.   , 0.   , 0.   , 0.   , 0.   , 0.0754717 ,  0.52830189, 0.39622642]], dict, threshholds
                else:  # if IAT > 167246344.0
                    dict['IAT'] = IAT
                    threshholds.append(['IAT', '>', 167246344.0])
                    return [[0., 0., 0., 0., 0., 0., 0., 1.]], dict, threshholds

def categorize_std(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.38:
        return 'low'
    elif value <= 9.8:
        return 'medium'
    else:
        return 'high'

def categorize_rst_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.5:
        return 'level 1'
    elif value <= 1.32:
        return 'level 2'
    elif value <= 4.3:
        return 'level 3'
    elif value <= 5.44:
        return 'level 4'
    elif value <= 39.4:
        return 'level 5'
    elif value <= 89.1:
        return 'level 6'
    elif value <= 115.55:
        return 'level 7'
    elif value <= 178.75:
        return 'level 8'
    elif value <= 240.9:
        return 'level 9'
    elif value <= 284.45:
        return 'level 10'
    elif value <= 287.0:
        return 'level 11'
    elif value <= 732.1:
        return 'level 12'
    elif value <= 1266.6:
        return 'level 13'
    elif value <= 6170.85:
        return 'level 14'
    else:
        return 'level 15'
    
def categorize_magnitude(value):
    if value == 0.0:
        return 'zero'
    elif value <= 10.39:
        return 'level 1'
    elif value <= 10.63:
        return 'level 2'
    elif value <= 10.68:
        return 'level 3'
    elif value <= 11.04:
        return 'level 4'
    elif value <= 11.12:
        return 'level 5'
    elif value <= 11.14:
        return 'level 6'
    elif value <= 53.6:
        return 'level 7'
    else:
        return 'level 8'

def categorize_tot_size(value):
    if value == 0.0:
        return 'zero'
    elif value <= 56.38:
        return 'level 1'
    elif value <= 66.45:
        return 'level 2'
    elif value <= 85.75:
        return 'level 3'
    elif value <= 98.2:
        return 'level 4'
    elif value <= 292.18:
        return 'level 5'
    elif value <= 350.8:
        return 'level 6'
    elif value <= 478.82:
        return 'level 7'
    elif value <= 902.01:
        return 'level 8'
    elif value <= 2347.6:
        return 'level 9'
    else:
        return 'level 10'

def categorize_number(value):
    if value == 0.0:
        return 'zero'
    elif value <= 6.0:
        return 'level 1'
    elif value <= 7.01:
        return 'level 2'
    elif value <= 7.5:
        return 'level 3'
    elif value <= 9.28:
        return 'level 4'
    elif value <= 9.5:
        return 'level 5'
    elif value <= 9.56:
        return 'level 6'
    elif value <= 11.5:
        return 'level 7'
    elif value <= 12.75:
        return 'level 8'
    else:
        return 'level 9'

def categorize_avg(value):
    if value == 0.0:
        return 'zero'
    elif value <= 53.88:
        return 'level 1'
    elif value <= 55.42:
        return 'level 2'
    elif value <= 56.22:
        return 'level 3'
    elif value <= 59.13:
        return 'level 4'
    elif value <= 60.58:
        return 'level 5'
    elif value <= 66.04:
        return 'level 6'
    elif value <= 98.91:
        return 'level 7'
    elif value <= 203.92:
        return 'level 8'
    elif value <= 380.76:
        return 'level 9'
    elif value <= 1382.54:
        return 'level 10'
    else:
        return 'level 11'

def categorize_radius(value):
    if value == 0.0:
        return 'zero'
    elif value <= 5.41:
        return 'level 1'
    elif value <= 5.87:
        return 'level 2'
    elif value <= 8.31:
        return 'level 3'
    elif value <= 48.07:
        return 'level 4'
    elif value <= 56.66:
        return 'level 5'
    elif value <= 69.8:
        return 'level 6'
    elif value <= 81.55:
        return 'level 7'
    elif value <= 278.51:
        return 'level 8'
    elif value <= 753.63:
        return 'level 9'
    else:
        return 'level 10'

def categorize_tot_sum(value):
    if value == 0.0:
        return 'zero'
    elif value <= 303.1:
        return 'level 1'
    elif value <= 354.75:
        return 'level 2'
    elif value <= 435.1:
        return 'level 3'
    elif value <= 442.75:
        return 'level 4'
    elif value <= 557.26:
        return 'level 5'
    elif value <= 700.96:
        return 'level 6'
    elif value <= 1398.8:
        return 'level 7'
    elif value <= 1616.65:
        return 'level 8'
    elif value <= 3884.2:
        return 'level 9'
    elif value <= 37934.4:
        return 'level 10'
    else:
        return 'level 11'

def categorize_syn_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.05:
        return 'level 1'
    elif value <= 0.1:
        return 'level 2'
    elif value <= 0.15:
        return 'level 3'
    elif value <= 0.25:
        return 'level 4'
    elif value <= 0.29:
        return 'level 5'
    elif value <= 0.45:
        return 'level 6'
    elif value <= 0.65:
        return 'level 7'
    elif value <= 0.7:
        return 'level 8'
    elif value <= 1.55:
        return 'level 9'
    elif value <= 1.7:
        return 'level 10'
    elif value <= 1.75:
        return 'level 11'
    else:
        return 'level 12'

def categorize_flow_duration(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.15:
        return 'level 1'
    elif value <= 0.2:
        return 'level 2'
    elif value <= 0.39:
        return 'level 3'
    elif value <= 0.59:
        return 'level 4'
    elif value <= 3.07:
        return 'level 5'
    elif value <= 3.52:
        return 'level 6'
    elif value <= 17.93:
        return 'level 7'
    elif value <= 20.54:
        return 'level 8'
    elif value <= 38.82:
        return 'level 9'
    elif value <= 72.36:
        return 'level 10'
    elif value <= 516.47:
        return 'level 11'
    else:
        return 'level 12'

def categorize_weight(value):
    if value == 0.0:
        return 'zero'
    elif value <= 77.83:
        return 'level 1'
    elif value <= 79.94:
        return 'level 2'
    elif value <= 83.68:
        return 'level 3'
    elif value <= 90.03:
        return 'level 4'
    elif value <= 126.97:
        return 'level 5'
    elif value <= 140.4:
        return 'level 6'
    elif value <= 193.08:
        return 'level 7'
    else:
        return 'level 8'

def categorize_duration(value):
    if value == 0.0:
        return 'zero'
    elif value <= 54.0:
        return 'level 1'
    elif value <= 57.0:
        return 'level 2'
    elif value <= 61.5:
        return 'level 3'
    elif value <= 62.75:
        return 'level 4'
    elif value <= 84.4:
        return 'level 5'
    elif value <= 100.6:
        return 'level 6'
    elif value <= 116.55:
        return 'level 7'
    elif value <= 160.4:
        return 'level 8'
    elif value <= 246.5:
        return 'level 9'
    else:
        return 'level 10'

def categorize_srate(value):
    if value == 0.0:
        return 'zero'
    elif value <= 1.34:
        return 'level 1'
    elif value <= 6.95:
        return 'level 2'
    elif value <= 22.49:
        return 'level 3'
    elif value <= 29.92:
        return 'level 4'
    elif value <= 34.16:
        return 'level 5'
    elif value <= 73.62:
        return 'level 6'
    elif value <= 107.41:
        return 'level 7'
    elif value <= 695.91:
        return 'level 8'
    else:
        return 'level 9'

def categorize_covariance(value):
    if value == 0.0:
        return 'zero'
    elif value <= 1.12:
        return 'level 1'
    elif value <= 90.4:
        return 'level 2'
    elif value <= 97.33:
        return 'level 3'
    elif value <= 4959.5:
        return 'level 4'
    elif value <= 6269.43:
        return 'level 5'
    elif value <= 18379.3:
        return 'level 6'
    elif value <= 19281.41:
        return 'level 7'
    elif value <= 81486.11:
        return 'level 8'
    elif value <= 86125.98:
        return 'level 9'
    elif value <= 915674.0:
        return 'level 10'
    elif value <= 1051078.34:
        return 'level 11'
    elif value <= 2317899.75:
        return 'level 12'
    else:
        return 'level 13'

def categorize_min(value):
    if value == 0.0:
        return 'zero'
    elif value <= 52.0:
        return 'level 1'
    elif value <= 60.5:
        return 'level 2'
    elif value <= 67.7:
        return 'level 3'
    elif value <= 67.95:
        return 'level 4'
    elif value <= 290.12:
        return 'level 5'
    elif value <= 786.0:
        return 'level 6'
    elif value <= 1504.0:
        return 'level 7'
    else:
        return 'level 8'

def categorize_max(value):
    if value == 0.0:
        return 'zero'
    elif value <= 54.2:
        return 'level 1'
    elif value <= 64.31:
        return 'level 2'
    elif value <= 74.7:
        return 'level 3'
    elif value <= 80.8:
        return 'level 4'
    elif value <= 90.5:
        return 'level 5'
    elif value <= 140.5:
        return 'level 6'
    elif value <= 364.0:
        return 'level 7'
    elif value <= 466.88:
        return 'level 8'
    elif value <= 873.25:
        return 'level 9'
    elif value <= 3076.5:
        return 'level 10'
    elif value <= 3093.8:
        return 'level 11'
    else:
        return 'level 12'

def categorize_header_length(value):
    if value == 0.0:
        return 'zero'
    elif value <= 7715.2:
        return 'level 1'
    elif value <= 23286.3:
        return 'level 2'
    elif value <= 27577.7:
        return 'level 3'
    elif value <= 82721.44:
        return 'level 4'
    elif value <= 150021.5:
        return 'level 5'
    elif value <= 156572.95:
        return 'level 6'
    elif value <= 180764.0:
        return 'level 7'
    elif value <= 220049.1:
        return 'level 8'
    elif value <= 221395.0:
        return 'level 9'
    elif value <= 427410.41:
        return 'level 10'
    elif value <= 1000736.09:
        return 'level 11'
    else:
        return 'level 12'

def categorize_rate(value):
    if value == 0.0:
        return 'zero'
    elif value <= 3.37:
        return 'level 1'
    elif value <= 7.23:
        return 'level 2'
    elif value <= 25.51:
        return 'level 3'
    elif value <= 28.62:
        return 'level 4'
    elif value <= 74.44:
        return 'level 5'
    elif value <= 106.78:
        return 'level 6'
    elif value <= 114.73:
        return 'level 7'
    elif value <= 292.85:
        return 'level 8'
    elif value <= 372.16:
        return 'level 9'
    elif value <= 1169.08:
        return 'level 10'
    else:
        return 'level 11'

def categorize_urg_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 12.1:
        return 'level 1'
    elif value <= 14.65:
        return 'level 2'
    elif value <= 36.65:
        return 'level 3'
    elif value <= 64.35:
        return 'level 4'
    elif value <= 86.1:
        return 'level 5'
    elif value <= 188.85:
        return 'level 6'
    elif value <= 340.9:
        return 'level 7'
    else:
        return 'level 8'

def categorize_fin_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.05:
        return 'extremely low'
    elif value <= 0.08:
        return 'low'
    elif value <= 0.32:
        return 'midly low'
    elif value <= 0.35:
        return 'midly high'
    elif value <= 0.47:
        return 'high'
    else:
        return 'extremely high'

def categorize_ack_count(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.02:
        return 'low'
    elif value <= 0.13:
        return 'medium'
    else:
        return 'high'

def categorize_variance(value):
    if value == 0.0:
        return 'zero'
    elif value <= 0.39:
        return 'extremely low'
    elif value <= 0.64:
        return 'low'
    elif value <= 0.83:
        return 'midly low'
    elif value <= 0.95:
        return 'midly high'
    elif value <= 0.97:
        return 'high'
    else:
        return 'extremely high'

def categorize_iat(value):
    if value == 0.0:
        return 'zero'
    if value <= 0.02:
        return 'extremely low'
    if value <= 41462904.01:
        return 'low'
    if value <= 78690612.0:
        return 'midly low'
    if value <= 83469472.0:
        return 'medium'
    if value <= 133481500.0:
        return 'midly high'
    if value <= 167246344.0:
        return 'high' 
    else:
        return 'extremely high'
    
#used when value is zero
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

feature_descriptions = {
    'ts': "Timestamp",
    'flow_duration': "On a scale from Level 1 to Level 12, the Duration of the packet's flow",
    'Header_Length': "On a scale from Level 1 to Level 12, Packet header length",
    'Protocol_Type': "Protocol type",
    'Duration': "On a scale from Level 1 to Level 10, Time-to-Live",
    'Rate': "On a scale from Level 1 to Level 11, Rate of packet transmission",
    'Srate': "On a scale from Level 1 to Level 9, Rate of outbound packets transmission",
    'Drate': "Rate of inbound packets transmission",
    'fin_flag_number': "Count of FIN flags (which signal the end of data transmission)",
    'syn_flag_number': "Count of SYN flags (indicating the initiation of a TCP three-way handshake)",
    'rst_flag_number': "Count of RST flags (used for resetting connections)",
    'psh_flag_number': "Count of PSH flags (instructing to push buffered data to the receiving application)",
    'ack_flag_number': "Count of ACK flags (used to acknowledge packet receipts)",
    'ece_flag_number': "Count of ECE flags (indicating network congestion)",
    'cwr_flag_number': "Count of CWR flags (signaling reduced transmission rate due to congestion notification)",
    'ack_count': "Number of packets with an ACK flag",
    'syn_count': "On a scale from Level 1 to Level 12, Number of packets with a SYN flag",
    'fin_count': "Number of packets with a FIN flag",
    'urg_count': "On a scale from Level 1 to Level 8, Number of packets with an URG flag",
    'rst_count': "On a scale from Level 1 to Level 15, number of packets with an RST flag",
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
    'Tot_sum': "On a scale from Level 1 to Level 11, Total sum of packets lengths",
    'Min': "On a scale from Level 1 to Level 8, Minimum packet length in the flow",
    'Max': "On a scale from Level 1 to Level 12, Maximum packet length in the flow",
    'AVG': "On a scale from Level 1 to Level 11, average packet length in the flow",
    'Std': "Standard deviation of packet length",
    'Tot_size': "On a scale from Level 1 to Level 10, Packet's length",
    'IAT': "The time difference between two consecutive packets",
    'Number': "On a scale from Level 1 to Level 9, the total number of packets",
    'Magnitue': "On a scale from Level 1 to Level 8, Magnitude (calculated as the mean of the average lengths of incoming and outgoing packets in the flow)",
    'Radius': "On a scale from Level 1 to Level 10, Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets)",
    'Covariance': "On a scale from Level 1 to Level 13, Covariance (coveriance of the lengths of incoming and outgoing packets)",
    'Variance': "Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets)",
    'Weight': "On a scale from Level 1 to Level 8, Weight (calculated as the product of the counts of incoming and outgoing packets)"
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

    # Read the file and search for the pattern
    with open('natural_language_form/1_decision_tree_rule-9-natrual_language.txt', 'r') as file:
        for line in file:
            if search_string in line:
                # Extract probability
                prob_match = re.search(r"\(proba: (\d+\.\d+)%\)", line)
                if prob_match:
                    return float(prob_match.group(1))  # Return as float percentage
    #print(search_string)
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
    with open('natural_language_form/1_decision_tree_rule-9-natrual_language.txt', 'r') as file:
        for line in file:
            if search_string in line:
                # Extract probability
                prob_match = re.search(r"\(proba: (\d+\.\d+)%\)", line)
                if prob_match:
                    return search_string  # Return as float percentage
    #print(search_string)
    return None

def get_prediction_path(row):
    prediction_probs, dict, thresholds = predict(*row[:-4])

    if 'Std' in dict:
        dict['Std'] = categorize_std(dict['Std'])
    if 'IAT' in dict:
        dict['IAT'] = categorize_iat(dict['IAT'])
    if 'rst_count' in dict:
        dict['rst_count'] = categorize_rst_count(dict['rst_count'])
    if 'Magnitue' in dict:
        dict['Magnitue'] = categorize_magnitude(dict['Magnitue'])
    if 'Tot_size' in dict:
        dict['Tot_size'] = categorize_tot_size(dict['Tot_size'])
    if 'Number' in dict:
        dict['Number'] = categorize_number(dict['Number'])
    if 'AVG' in dict:
        dict['AVG'] = categorize_avg(dict['AVG'])
    if 'Radius' in dict:
        dict['Radius'] = categorize_radius(dict['Radius'])
    if 'Tot_sum' in dict:
        dict['Tot_sum'] = categorize_tot_sum(dict['Tot_sum'])
    if 'syn_count' in dict:
        dict['syn_count'] = categorize_syn_count(dict['syn_count'])
    if 'flow_duration' in dict:
        dict['flow_duration'] = categorize_flow_duration(dict['flow_duration'])
    if 'Weight' in dict:
        dict['Weight'] = categorize_weight(dict['Weight'])
    if 'Duration' in dict:
        dict['Duration'] = categorize_duration(dict['Duration'])
    if 'Srate' in dict:
        dict['Srate'] = categorize_srate(dict['Srate'])
    if 'Covariance' in dict:
        dict['Covariance'] = categorize_covariance(dict['Covariance'])
    if 'Min' in dict:
        dict['Min'] = categorize_min(dict['Min'])
    if 'Max' in dict:
        dict['Max'] = categorize_max(dict['Max'])
    if 'Header_Length' in dict:
        dict['Header_Length'] = categorize_header_length(dict['Header_Length'])
    if 'Rate' in dict:
        dict['Rate'] = categorize_rate(dict['Rate'])
    if 'urg_count' in dict:
        dict['urg_count'] = categorize_urg_count(dict['urg_count'])
    if 'fin_count' in dict:
        dict['fin_count'] = categorize_fin_count(dict['fin_count'])
    if 'ack_count' in dict:
        dict['ack_count'] = categorize_ack_count(dict['ack_count'])
    if 'Variance' in dict:
        dict['Variance'] = categorize_variance(dict['Variance'])
        
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

partial_df.to_csv('processed/1_5000.csv', index=False)
percentage_matching = (partial_df['prediction'] == partial_df['label']).mean() * 100
mismatch = (partial_df['prediction'] != partial_df['label']).sum()
print(f"5000_accuracy: {percentage_matching:.2f}%")
print(f"mismatch: {mismatch}")
