# Transforming Network Intrusion Detection Using Large Language Models

This repository contains the code implementation for the paper titled "Transforming Network Intrusion Detection Using Large Language Models." The project enhances network intrusion detection by integrating decision trees with large language models (LLMs) to improve classification accuracy and interpretability. It includes both complete and missing feature scenarios, demonstrating the robustness of various AI models. Examples from the GPT-1106-preview model are also provided to illustrate the performance and reasoning capabilities of the models in handling different network traffic types.

## Workflow Overview

This section provides an overview of the workflow used in this project, as illustrated in the flowchart below.

![Workflow Chart](flowchart.png)

1. **Decision Tree Creation**:
    - The process begins with labeled tabular data containing various features related to network traffic.
    - Two decision trees are created using the training data. Each tree is independently trained with different random seeds, ensuring diversity in the decision-making process.

2. **Path Extraction**:
    - Once the decision trees are trained, paths from the root to the leaf nodes are extracted. These paths represent the decision-making process of each tree.
    - Each path is associated with a specific prediction and a confidence score, indicating the model's certainty in its prediction.

3. **Path Serialization**:
    - The extracted paths are serialized into a more interpretable format. For instance, numerical feature values are translated into descriptive levels.
    - This step helps in making the decision paths understandable, highlighting key features and their impact on the prediction.

4. **LLM for Prediction and Explanation**:
    - The serialized paths, along with the confidence scores, are fed into a Large Language Model (LLM) for final prediction and explanation.
    - The LLM analyzes the provided paths and generates a prediction for the type of network traffic. Additionally, it offers a rationale for its decision, ensuring transparency and interpretability in the classification process.

This workflow leverages the strengths of both decision trees and LLMs to provide accurate and explainable network traffic classification, as detailed in the paper "Transforming Network Intrusion Detection Using Large Language Models."

## Project Dependencies

- **python**: 3.11.7
- **scikit-learn**: 1.4.2
- **pandas**: 2.2.2
- **openai**: 1.10.0
- **numpy**: 1.26.3

## Experiment reproduction

## Test Dataset

For our experiments, we used a test set of 5,000 samples from the [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) dataset. This test set is used to evaluate the performance of our models in predicting and explaining network intrusion types.

## 8 Categories Network traffic prediction without missing features
Note: Two Different decision trees are already trained. For more setting details of Two different trees, please refer to:
1. 1st Decision tree: `dt_17.py`
2. 2nd Decision tree: `dt_2.py`

Both files are under `Code_Base/Unmissing_features/8_categories(decision tree + LLM)/Part1(Decision trees training + Path Extraction+Serialization)/script`

1. **Extract and Serialized decision tree paths of Two different decision trees with the default test file**

   

## 8 Categories Network traffic prediction with missing features

