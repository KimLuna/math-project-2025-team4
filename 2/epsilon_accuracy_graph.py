import matplotlib.pyplot as plt

epsilon_vals = [1e-2, 1e-4, 1e-6, 1e-8, 1e-9, 1e-10]

accuracy = [94, 94, 94, 94, 94, 94]
precision = [70, 70, 70, 70, 70, 70]
recall = [89, 89, 89, 89, 89, 89]

plt.figure(figsize=(8, 6))
plt.plot(epsilon_vals, accuracy, marker="o", label="Accuracy")
plt.plot(epsilon_vals, precision, marker="o", label="Precision")
plt.plot(epsilon_vals, recall, marker="o", label="Recall")

plt.xscale("log")

plt.xlabel("Epsilon (variance smoothing, log scale)")
plt.ylabel("Percentage (%)")
plt.title("Parameter Tuning: Effect of Epsilon on Naive Bayes Performance")
plt.legend()
plt.grid(True)

plt.savefig("nb_tuning_graph.png", dpi=300)

plt.show()
