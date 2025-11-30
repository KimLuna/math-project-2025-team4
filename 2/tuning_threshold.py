import os
import logging
import math
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from bayes import load_raw_data, training, predict, select_features, data_filtering


def evaluate(predictions, answers):
    correct = sum([predictions[i] == answers[i] for i in range(len(predictions))])
    accuracy = round(correct / len(answers), 2) * 100

    # predictions과 answer을 비교해서 성능 평가

    # 정확도: 전체 중 맞춘 비율
    tp = sum([(predictions[i] == 1 and answers[i] == 1) for i in range(len(answers))])
    # 정밀도: 1이라고 예측한 것 중 실제로 1인 비율
    fp = sum([(predictions[i] == 1 and answers[i] == 0) for i in range(len(answers))])
    # 재현율: 실제로 1인 것 중에 올바르게 예측한 비율
    fn = sum([(predictions[i] == 0 and answers[i] == 1) for i in range(len(answers))])

    precision = round(tp / (tp + fp), 2) * 100 if (tp + fp) > 0 else 0
    recall = round(tp / (tp + fn), 2) * 100 if (tp + fn) > 0 else 0

    return accuracy, precision, recall

# threshold tuning & figure generate
def threshold_tuning(train_file, test_file):
    train_instances, train_labels = load_raw_data(train_file)
    test_instances, test_labels = load_raw_data(test_file)

    threshold_vals = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
    accuracy_list, precision_list, recall_list = [], [], []

    for threshold in threshold_vals:
        # 중요 feature만 남김 & 남은 feature만으로 데이터셋 구성 및 학습
        selected_idx = select_features(train_instances, threshold)
        train_filtered = data_filtering(train_instances, selected_idx)
        test_filtered = data_filtering(test_instances, selected_idx)

        params = training(train_filtered, train_labels)
        preds = [predict(x, params) for x in test_filtered]

        acc, prec, rec = evaluate(preds, test_labels)
        accuracy_list.append(acc)
        precision_list.append(prec)
        recall_list.append(rec)

        print(f"Threshold {threshold:.2f} -> Accuracy: {acc}%, Precision: {prec}%, Recall: {rec}%")

    # 그래프 출력
    plt.figure(figsize=(8, 6))
    plt.plot(threshold_vals, accuracy_list, marker='o', label='Accuracy')
    plt.plot(threshold_vals, precision_list, marker='s', label='Precision')
    plt.plot(threshold_vals, recall_list, marker='^', label='Recall')

    plt.xlabel('Feature Selection Threshold')
    plt.ylabel('Performance (%)')
    plt.title('Naive Bayes Performance vs Threshold')
    plt.legend()
    plt.grid(True)
    plt.savefig("threshold_tuning_graph.png", dpi=300)
    plt.show()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    threshold_tuning("training.csv", "testing.csv")