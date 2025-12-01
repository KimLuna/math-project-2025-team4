import logging
import math
import matplotlib.pyplot as plt
from bayes import load_raw_data, predict, select_features, data_filtering, training


def evaluate(predictions, answers):
    # predictions과 answer을 비교해서 성능 평가
    # 정확도: 전체 중 맞춘 비율
    correct = sum([predictions[i] == answers[i] for i in range(len(predictions))])
    accuracy = round(correct / len(answers), 2) * 100

    tp = sum([(predictions[i] == 1 and answers[i] == 1) for i in range(len(answers))])
    fp = sum([(predictions[i] == 1 and answers[i] == 0) for i in range(len(answers))])
    fn = sum([(predictions[i] == 0 and answers[i] == 1) for i in range(len(answers))])
    # 정밀도: 1이라고 예측한 것 중 실제로 1인 비율
    precision = round(tp / (tp + fp), 2) * 100 if (tp + fp) > 0 else 0
    # 재현율: 실제로 1인 것 중에 올바르게 예측한 비율
    recall = round(tp / (tp + fn), 2) * 100 if (tp + fn) > 0 else 0

    return accuracy, precision, recall

# epsilon tuning & figure generate
def epsilon_tuning(train_file, test_file):
    train_instances, train_labels = load_raw_data(train_file)
    test_instances, test_labels = load_raw_data(test_file)

    epsilon_vals = [1e-10, 1e-8, 1e-6, 1e-4, 1e-2, 1e-1, 1, 10]
    accuracy_list, precision_list, recall_list = [], [], []

    selected_idx = select_features(train_instances, threshold=0.8)
    train_filtered = data_filtering(train_instances, selected_idx)
    test_filtered = data_filtering(test_instances, selected_idx)

    for epsilon in epsilon_vals:
        params = training(train_filtered, train_labels, epsilon=epsilon)
        predictions = [predict(x, params) for x in test_filtered]
        acc, prec, rec = evaluate(predictions, test_labels)

        accuracy_list.append(acc)
        precision_list.append(prec)
        recall_list.append(rec)

        print(f"epsilon {epsilon:.0e} -> Accuracy: {acc}%, Precision: {prec}%, Recall: {rec}%")

    # 시각화
    plt.figure(figsize=(8, 6))
    plt.plot(epsilon_vals, accuracy_list, marker='o', label='Accuracy')
    plt.plot(epsilon_vals, precision_list, marker='s', label='Precision')
    plt.plot(epsilon_vals, recall_list, marker='^', label='Recall')

    plt.xscale('log')
    plt.xlabel('epsilon (variance smoothing)')
    plt.ylabel('Performance (%)')
    plt.title('Naive Bayes Performance vs epsilon')
    plt.legend()
    plt.grid(True)
    plt.savefig("epsilon_tuning_graph.png", dpi=300)
    plt.show()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    epsilon_tuning("training.csv", "testing.csv")
