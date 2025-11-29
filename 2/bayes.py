import os
import sys
import argparse
import logging
import math

# Additional Task용 라이브러리
import numpy as np
import pandas as pd


def training(instances, labels):
    # 데이터를 학습하여 클래스별 평균, 분산, 사전 확률을 계산
    separated_data = {}
    for i in range(len(instances)):
        vector = instances[i][1:]
        class_val = labels[i]

        if class_val not in separated_data:
            separated_data[class_val] = []
        separated_data[class_val].append(vector)

    parameters = {}
    total_rows = len(instances)

    # 1. 각 클래스별 통계치(평균, 분산, 사전확률) 계산
    for class_val, rows in separated_data.items():
        summary = {}

        n_samples = len(rows)  # row 수
        n_features = len(rows[0])  # feature 수

        # 1-1. 사전 확률 P(Class) 계산
        summary["prior"] = n_samples / total_rows

        # 1-2. 평균 계산
        means = []
        for i in range(n_features):
            col_values = [row[i] for row in rows]
            means.append(sum(col_values) / n_samples)
        summary["mean"] = means

        # 1-3. 분산 계산
        variances = []
        for i in range(n_features):
            col_values = [row[i] for row in rows]
            mu = means[i]
            var = sum([(x - mu) ** 2 for x in col_values]) / n_samples
            variances.append(var + 1e-9)  # 분산이 0이 될 때의 나눗셈 오류 방지
        summary["var"] = variances
        parameters[class_val] = summary
    return parameters


def predict(instance, parameters):
    # 학습된 파라미터를 사용하여 테스트 데이터의 클래스를 예측
    features = instance[1:]

    best_label = None
    best_prob = -float("inf")

    for class_val, params in parameters.items():
        probability = math.log(params["prior"])

        means = params["mean"]
        vars = params["var"]

        for i in range(len(features)):
            x = features[i]
            mean = means[i]
            var = vars[i]

            exponent = -((x - mean) ** 2) / (2 * var)
            loglikelihood = -0.5 * math.log(2 * math.pi * var) + exponent

            probability += loglikelihood

        if probability > best_prob:
            best_prob = probability
            best_label = class_val

    return best_label


def report(predictions, answers):
    if len(predictions) != len(answers):
        logging.error("The lengths of two arguments should be same")
        sys.exit(1)

    # accuracy
    correct = 0
    for idx in range(len(predictions)):
        if predictions[idx] == answers[idx]:
            correct += 1
    accuracy = round(correct / len(answers), 2) * 100

    # precision
    tp = 0
    fp = 0
    for idx in range(len(predictions)):
        if predictions[idx] == 1:
            if answers[idx] == 1:
                tp += 1
            else:
                fp += 1
    if (tp + fp) > 0:  # ZeroDivisionError
        precision = round(tp / (tp + fp), 2) * 100

    # recall
    tp = 0
    fn = 0
    for idx in range(len(answers)):
        if answers[idx] == 1:
            if predictions[idx] == 1:
                tp += 1
            else:
                fn += 1
    recall = 0
    if (tp + fn) > 0:  # ZeroDivisionError
        recall = round(tp / (tp + fn), 2) * 100

    logging.info("accuracy: {}%".format(accuracy))
    logging.info("precision: {}%".format(precision))
    logging.info("recall: {}%".format(recall))


def load_raw_data(fname):
    instances = []
    labels = []
    with open(fname, "r") as f:
        f.readline()
        for line in f:
            tmp = line.strip().split(", ")
            tmp[1] = float(tmp[1])
            tmp[2] = float(tmp[2])
            tmp[3] = float(tmp[3])
            tmp[4] = float(tmp[4])
            tmp[5] = int(tmp[5])
            tmp[6] = int(tmp[6])
            tmp[7] = float(tmp[7])
            tmp[8] = int(tmp[8])
            instances.append(tmp[:-1])
            labels.append(tmp[-1])
    return instances, labels

def select_features(instances, threshold = 0.9):
    # 특성 선택 자동화 함수: 상관계수 높은 특성 찾기
    df = pd.DataFrame(instances)
    features = df.iloc[:, 1:].astype(float)

    corr_matrix = features.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k = 1).astype(bool))

    column_drop = [column for column in upper.columns if any(upper[column] > threshold)]
    column_keep = [0] + [c for c in features.columns if c not in column_drop]

    return column_keep

def data_filtering(instances, indices):
    # 선택된 인덱스 데이터만 남기기
    return [[row[i] for i in indices] for row in instances]

def run(train_file, test_file):
    print("Feature Set 1: Baseline (모든 특성)")
    # training phase
    instances, labels = load_raw_data(train_file)
    logging.debug("instances: {}".format(instances))
    logging.debug("labels: {}".format(labels))
    parameters = training(instances, labels)

    # testing phase
    instances, labels = load_raw_data(test_file)
    predictions = []
    for instance in instances:
        result = predict(instance, parameters)

        if result not in [0, 1]:
            logging.error("The result must be either 0 or 1")
            sys.exit(1)

        predictions.append(result)

    # report
    report(predictions, labels)

    # Feature Engineering & Parameter tuning
    print("Feature Set 2: 상관계수를 통한 Feature Selection 자동화")
    train_instances, train_labels = load_raw_data(train_file)
    test_instances, test_labels = load_raw_data(test_file)

    selected_idx = select_features(train_instances, threshold = 0.9)
    print(f"Selected Feature: {selected_idx}")

    train_set2 = data_filtering(train_instances, selected_idx)
    test_set2 = data_filtering(test_instances, selected_idx)

    params_set2 = training(train_set2, train_labels)
    predictions_set2 = []
    for instance in test_set2:
        result = predict(instance, params_set2)
        predictions_set2.append(result)

    report(predictions_set2, test_labels)


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--training",
        required=True,
        metavar="<file path to the training dataset>",
        help="File path of the training dataset",
        default="training.csv",
    )
    parser.add_argument(
        "-u",
        "--testing",
        required=True,
        metavar="<file path to the testing dataset>",
        help="File path of the testing dataset",
        default="testing.csv",
    )
    parser.add_argument(
        "-l",
        "--log",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )

    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)

    if not os.path.exists(args.training):
        logging.error("The training dataset does not exist: {}".format(args.training))
        sys.exit(1)

    if not os.path.exists(args.testing):
        logging.error("The testing dataset does not exist: {}".format(args.testing))
        sys.exit(1)

    run(args.training, args.testing)


if __name__ == "__main__":
    main()
