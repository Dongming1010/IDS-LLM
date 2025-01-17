# Network Intrusion Detection Using Large Language Models

## Introduction

This document presents examples of responses generated by the GPT-1106-preview model in the context of network intrusion detection. The inputs include decision tree paths and their associated confidence rates. The responses are categorized into two main scenarios: with missing features and without missing features. Each section includes several examples to illustrate how the model handles these different scenarios.

## Without Missing Features

### Example 1: Benign Traffic

#### Path Descriptions and Confidence Rates

- **Label**: BenignTraffic
- **Prediction 1**: Web-Based
  - **Confidence rate**: 37.36%
  - **Path Description**: On a scale from Level 1 to Level 12, the Duration of the packet's flow is level 9. On a scale from Level 1 to Level 9, Rate of outbound packets transmission is level 3. On a scale from Level 1 to Level 15, number of packets with an RST flag is level 10. On a scale from Level 1 to Level 8, Minimum packet length in the flow is level 3. Standard deviation of packet length is zero. The time difference between two consecutive packets is extremely low. Application layer protocol is HTTPS.
- **Prediction 2**: BenignTraffic
  - **Confidence rate**: 52.55%
  - **Path Description**: On a scale from Level 1 to Level 11, Packet header length is level 5. Number of packets with an ACK flag is zero. On a scale from Level 1 to Level 9, total sum of packets lengths is level 1. The time difference between two consecutive packets is extremely low. On a scale from Level 1 to Level 10, Magnitude (calculated as the mean of the average lengths of incoming and outgoing packets in the flow) is level 3. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is zero. Weight (calculated as the product of the counts of incoming and outgoing packets) is low. Count of ACK flags (used to acknowledge packet receipts) is 1.0.

#### Model Response

Most likely type of traffic: BenignTraffic

The most plausible path is from the second tree.

**Rationale for choice:**

The path from the second tree has a higher prediction accuracy rate of 52.55%, compared to the 37.36% accuracy rate of the first tree. This alone suggests that the second tree's model is more reliable in making predictions.

Moreover, the characteristics described in the second tree's path are more consistent with what one would expect from benign traffic:

- The Packet header length being level 5 out of 11 does not necessarily indicate malicious activity.
- A zero count of ACK flags does not typically indicate malicious activity, perhaps the traffic volume in question was simply not captured during the session initiation phase where ACKs would be prevalent.
- A low total sum of packets lengths could be indicative of a light traffic session, commonly seen in benign activities.
- The extremely low time difference between two consecutive packets can be a sign of a fast network but is not in itself indicative of malicious behavior.
- The Magnitude being level 3 out of 10 indicates average packet sizes are small, which can occur in regular web browsing or similar activities.
- A Variance of zero in packet lengths between incoming and outgoing traffic suggests uniformity often seen in regular, expected traffic patterns.
- Having a low Weight suggests that the flow has a low number of incoming and outgoing packets, which can be normal for certain benign uses.
- Having a count of 1.0 ACK flags indicates normal TCP operation where packets are being acknowledged, as would be expected in benign traffic.

Compared to the first tree's path, the prediction of "Web-Based" attacks is based on path characteristics such as higher Duration of packet flow, rate of outbound packet transmission at a certain level, and significant number of packets with RST flag. These could potentially indicate an attack, but the standard deviation of packet length being zero and minimum packet length at level 3 could seem atypical for web-based attacks, which might exhibit more variation in packet sizes due to the complexity of web applications. Additionally, the application layer protocol being HTTPS suggests secure communications, which are less commonly associated with web-based attacks and not conclusive to that prediction.

Hence, the second tree's path is not only statistically more accurate but also qualitatively seems more consistent with characteristics of benign traffic.

### Insights on GPT-1106's Performance

GPT-1106 handles the task well by effectively integrating the provided path descriptions and confidence scores to make accurate predictions. The model excels in:

1. **Utilizing Confidence Scores**: GPT-1106 uses the confidence scores effectively to weigh the reliability of each path, favoring paths with higher accuracy rates. For instance, in Example 1, GPT-1106 correctly identifies the path with a 52.55% accuracy rate as more reliable compared to the 37.36% accuracy rate, indicating its ability to prioritize paths based on their statistical reliability.

2. **Contextual Understanding**: The model demonstrates a strong understanding of the context provided in the path descriptions. It accurately associates specific features with benign or malicious activities. For example, GPT-1106 correctly identifies that features such as low total sum of packet lengths, extremely low time difference between packets, and the presence of ACK flags align more with benign traffic characteristics, showcasing its ability to interpret nuanced data accurately.

3. **Detailed Reasoning**: GPT-1106 provides detailed and logical rationales for its choices, explaining why certain path characteristics align with benign traffic. In Example 1, it articulates why features like low weight and the presence of ACK flags are indicative of benign traffic, while the high duration and RST flag count from the first path may suggest potential attacks. This ability to provide comprehensive explanations enhances the transparency of its decision-making process.

By leveraging these capabilities, GPT-1106 not only makes accurate predictions but also offers clear and understandable justifications, making it a valuable tool for network intrusion detection.

### Example 2: Recon Traffic

#### Path Descriptions and Confidence Rates

- **Label**: Recon
- **Prediction 1**: Recon
  - **Confidence rate**: 42.62%
  - **Path Description**: On a scale from Level 1 to Level 12, Number of packets with a SYN flag is level 6. Number of packets with a FIN flag is zero. Standard deviation of packet length is high. The time difference between two consecutive packets is high. On a scale from Level 1 to Level 10, Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets) is level 7. On a scale from Level 1 to Level 13, Covariance (covariance of the lengths of incoming and outgoing packets) is level 4.
- **Prediction 2**: Web-Based
  - **Confidence rate**: 45.85%
  - **Path Description**: Rate of packet transmission is mildly low. On a scale from Level 1 to Level 9, total sum of packets lengths is level 5. On a scale from Level 1 to Level 9, Minimum packet length in the flow is level 3. The time difference between two consecutive packets is medium. Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets) is medium. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high. Count of SYN flags (indicating the initiation of a TCP three-way handshake) is 0.

#### Model Response

Most likely type of traffic: Recon

The most plausible path is from the second tree.

**Rationale:**

Although both decision trees appear to predict different types of attacks (Recon and Web-Based), the second tree's reported accuracy (45.85%) is higher than that of the first tree (42.62%), which suggests that the second tree's model is more reliable for prediction, at least judging by the provided accuracy rates alone.

However, considering the path descriptions more closely, the first tree's path description indicates several factors (such as a higher level of Radius and Covariance, the existence of SYN flags though not high in quantity, and a high standard deviation of packet length) which are more indicative of reconnaissance activity, where an attacker is gathering information about the network rather than exploiting a web vulnerability, which would be categorized as Web-Based. Recon attacks often involve analyzing the network packets in more detail, which could result in varied packet lengths and covariance levels.

Although the variance being extremely high might be indicative of a web-based attack, as predicted by the second tree, the presence of SYN packets is usually associated with attempting connections as part of the TCP three-way handshake, which is more aligned with Recon activities where an attacker might be scanning the network to understand its structure and find open ports or potential vulnerabilities.

Given that the specific path description seems more aligned with characteristics of recon activities and despite the slightly lower accuracy rate, the first tree's path conclusion should not be dismissed. Therefore, even though the second tree has a higher accuracy rate, the described metrics from the first tree align more closely with what is typically seen in reconnaissance activities, and thus I am inclined to believe the traffic aligns more with the Recon category from the first tree's prediction.

### Insights on GPT-1106's Performance

GPT-1106 demonstrates impressive decision-making skills by considering both statistical reliability and contextual relevance, even when paths have different confidence scores. In Example 2, the model chooses the path with a lower confidence rate (42.62%) over the higher one (45.85%) based on the contextual alignment of features with reconnaissance activities. This decision showcases the model's strengths in:

1. **Contextual Prioritization**: The model accurately identifies features like SYN flag presence and high variance in packet lengths as more indicative of reconnaissance activities, despite the lower confidence score. This suggests a deeper understanding of the nature of the traffic.

2. **Balancing Statistical and Contextual Insights**: GPT-1106 balances statistical confidence with the qualitative assessment of path descriptions. This nuanced approach enables it to favor paths that are contextually more aligned with the true nature of the traffic, even when their confidence scores are lower.

3. **Detailed and Logical Reasoning**: The model provides clear and logical explanations for its choices. It explains why the first tree's path features, such as high Radius and Covariance levels and SYN flag presence, are more consistent with reconnaissance activities than with web-based attacks. This level of detail enhances trust in the model's decision-making process.

These insights highlight GPT-1106's capability to integrate numerical confidence with contextual understanding, improving both the accuracy and interpretability of network intrusion detection.

### Example 3: DoS Traffic

#### Path Descriptions and Confidence Rates

- **Label**: DoS
- **Prediction 1**: DoS
  - **Confidence rate**: 58.33%
  - **Path Description**: Number of packets with an RST flag is zero. On a scale from Level 1 to Level 12, Maximum packet length in the flow is level 6. Standard deviation of packet length is high. The time difference between two consecutive packets is medium. On a scale from Level 1 to Level 9, the total number of packets is level 5. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is low.
- **Prediction 2**: Web-Based
  - **Confidence rate**: 37.38%
  - **Path Description**: On a scale from Level 1 to Level 11, Packet header length is level 4. On a scale from Level 1 to Level 15, Packet's length is level 2. The time difference between two consecutive packets is extremely low. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is mildly high. Count of ACK flags (used to acknowledge packet receipts) is 0.0.

#### Model Response

Most likely type of traffic: DoS

The most plausible path is from the first tree.

**Rationale:**

The rationale for this choice is that the path from the first decision tree is more aligned with what is typically expected in DoS traffic characteristics. For example, a DoS attack often involves sending many packets to overwhelm the target, which may correspond to a higher standard deviation of packet length due to the variability of attack payloads. The maximum packet length being at level 6 suggests that the packets are not minimal, which may support the characteristics of a DoS attack, as packets are often crafted in specific ways to exploit vulnerabilities or to maximize resource consumption. Additionally, a medium time difference between consecutive packets can also indicate a systematic transmission of packets, which is typical in DoS attacks, attempting to consume bandwidth or disrupt services.

Furthermore, the 'variance in packet lengths between incoming and outgoing packets' being low indicates that the flow may be unidirectional, which is often the case in DoS attacks where only the attack packets are flowing in one direction towards the victim and there may be very little legitimate traffic.

On the other hand, the path from the second decision tree describes packet characteristics that are typically not as strongly associated with Web-Based attacks. For example, Web-Based attacks like SQL injection or cross-site scripting (XSS) typically do not involve patterns with extremely low time differences between packets or a specific count of ACK flags.

Lastly, the accuracy rate associated with the first path's prediction is significantly higher (58.33%) compared to the second path's prediction accuracy rate of 37.38%, further supporting that the first path is more reliable for the given prediction. Hence, the combination of relevant traffic characteristics and a higher accuracy rate makes the path from the first tree more plausible for the type of traffic being analyzed.

### Insights on GPT-1106's Performance

GPT-1106 demonstrates its effectiveness in distinguishing between DoS and Web-Based attacks through:

1. **Accurate Differentiation**: The model effectively uses path descriptions to differentiate between DoS and Web-Based attacks, focusing on characteristics such as standard deviation of packet length, time differences between packets, and packet count, which are more indicative of DoS traffic. By analyzing these specific features, GPT-1106 can accurately classify the type of attack based on the patterns in the data.

2. **High Confidence Utilization**: GPT-1106 prioritizes paths with higher confidence rates, ensuring more reliable predictions. In this example, it correctly favors the path with 58.33% accuracy over the one with 37.38%. This approach increases the reliability of the model's predictions, making it more dependable for practical applications.

3. **Contextual Sensitivity**: The model understands the context provided by path descriptions, recognizing that features such as high standard deviation of packet lengths and medium time differences between packets are typical in DoS attacks. This sensitivity to context allows GPT-1106 to make more informed decisions, improving its overall performance.

## With Missing Features

### Example 1: Brute Force Attack

#### Path Descriptions

- **Label**: Brute_Force
- **First Tree Paths**:
  - **Path 1**:
    - **Description**: On a scale from Level 1 to Level 11, Rate of packet transmission is level 3. On a scale from Level 1 to Level 12, Number of packets with a SYN flag is level 9. On a scale from Level 1 to Level 15, number of packets with an RST flag is level 6. On a scale from Level 1 to Level 12, Maximum packet length in the flow is level 10. Standard deviation of packet length is high. The time difference between two consecutive packets is unknown. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high. Application layer protocol is HTTPS.
    - **Prediction**: Brute_Force
  - **Path 2**:
    - **Description**: Standard deviation of packet length is high. The time difference between two consecutive packets is unknown. On a scale from Level 1 to Level 10, Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets) is level 10.
    - **Prediction**: Web-Based
  - **Path 3**:
    - **Description**: On a scale from Level 1 to Level 12, Packet header length is level 3. On a scale from Level 1 to Level 9, Rate of outbound packets transmission is level 3. On a scale from Level 1 to Level 8, Number of packets with an URG flag is level 2. On a scale from Level 1 to Level 11, average packet length in the flow is level 10. Standard deviation of packet length is high. The time difference between two consecutive packets is unknown. On a scale from Level 1 to Level 10, Radius (calculated as the averaged variances of packet lengths for incoming and outgoing packets) is level 10. On a scale from Level 1 to Level 13, Covariance (covariance of the lengths of incoming and outgoing packets) is level 10.
    - **Prediction**: Spoofing
- **Second Tree Paths**:
  - **Path 1**:
    - **Description**: On a scale from Level 1 to Level 11, Packet header length is level 4. Number of packets with a FIN flag is zero. The time difference between two consecutive packets is unknown. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high. The ack (Acknowledgment) flag exists in this traffic.
    - **Prediction**: Brute_Force
  - **Path 2**:
    - **Description**: The time difference between two consecutive packets is unknown. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high.
    - **Prediction**: Brute_Force
  - **Path 3**:
    - **Description**: The time difference between two consecutive packets is unknown. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high. The ack (Acknowledgment) flag exists in this traffic.
    - **Prediction**: BenignTraffic
  - **Path 4**:
    - **Description**: On a scale from Level 1 to Level 11, number of packets with an URG flag is level 4. Number of packets with an RST flag is mildly low. The time difference between two consecutive packets is unknown. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high. The ack (Acknowledgment) flag exists in this traffic.
    - **Prediction**: Recon
  - **Path 5**:
    - **Description**: On a scale from Level 1 to Level 11, Packet header length is level 4. Rate of packet transmission is mildly high. On a scale from Level 1 to Level 9, total sum of packets lengths is level 8. Standard deviation of packet length is mildly high. The time difference between two consecutive packets is unknown. Variance (calculated as the ratio of variances in packet lengths between incoming and outgoing packets) is extremely high. Application layer protocol is HTTPS.
    - **Prediction**: Web-Based

**Most likely type of traffic**: Brute_Force

**Rationale**:
The most plausible path is from Path 1 of the first tree. The reason for choosing Path 1 from the first tree is that it provides a detailed description of several metrics that are synonymous with a possible Brute_Force attack. Here are the key points considered in the decision:

1. **Rate of packet transmission is at level 3**, which implies a consistent but not excessively rapid transmission rate. This is typical of Brute_Force attacks where attempts are made at a steady rate to guess credentials.
2. **Number of packets with a SYN flag at level 9** indicates many attempts to establish a TCP/IP connection, which is a common method used in Brute_Force attacks to repeatedly attempt communication with the target.
3. **Number of packets with an RST flag at level 6** can signify that multiple connections are being reset, which might be due to the repeated unsuccessful login attempts characteristic of Brute_Force attacks.
4. **Maximum packet length in the flow is at level 10** and high standard deviation of packet length can suggest varied sizes of payloads, possibly due to the transmission of different types of authentication data.
5. **The variance in packets is extremely high**, which also aligns with varied attempts at access which can be expected in Brute_Force scenarios.
6. **The application layer protocol being HTTPS** suggests that the traffic is encrypted; however, Brute_Force attacks can also occur against secure HTTP endpoints where attackers attempt to break into web application accounts.

Other paths also indicate high variance and unknown time differences between packets, but none provides as comprehensive a description that fits the profile of a Brute_Force attack as well as Path 1 from the first tree. It's also important to note that while 'unknown' features like the time difference between two consecutive packets cannot be assessed, the provided details in Path 1 offer enough information to make an educated prediction without this data.

### Insights on GPT-1106's Performance

GPT-1106 demonstrates notable proficiency in handling network traffic classification even with missing features:

1. **Detailed Analysis**: The model assesses the provided path descriptions comprehensively. For example, Path 1 from the first tree describes metrics such as the rate of packet transmission, SYN flag count, and maximum packet length, which are critical indicators of Brute Force attacks. The presence of high variance in packet lengths and a high number of SYN flags suggests repeated attempts to establish connections, aligning with Brute Force attack patterns.

2. **Handling Missing Features**: Despite missing values like the time difference between packets, GPT-1106 effectively uses the available data to make accurate predictions. The prompt indicates that missing features are marked as 'unknown,' and the model adapts by focusing on other relevant features.

3. **Contextual Understanding**: The model demonstrates a strong understanding of network traffic characteristics. It identifies that a high number of SYN flags and a high standard deviation of packet lengths are consistent with Brute Force attacks. The application layer protocol being HTTPS is also taken into account, suggesting that the attack could be targeting secure HTTP endpoints.

4. **Logical Reasoning**: GPT-1106 provides a clear and logical rationale for its choice. It explains why Path 1 from the first tree is more indicative of a Brute Force attack compared to other paths. The model emphasizes the significance of specific metrics, such as the high number of SYN flags and the consistent yet varied packet transmission rates.

5. **Confidence Assessment**: The model assesses the reliability of different paths, considering both the provided descriptions and the missing data. It confidently selects the most plausible path for the given scenario, demonstrating its robustness in handling incomplete information.

Overall, GPT-1106's ability to interpret complex path descriptions, handle missing features, and provide logical explanations highlights its effectiveness in network traffic classification tasks.
