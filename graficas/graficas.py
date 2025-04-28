import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("bench/op_promedios.csv")

# mantener orden lógico
orden = ["iterativo-32","concurrent-4","concurrent-16",
         "concurrent-32","concurrent-64"]
df["escenario"] = pd.Categorical(df.escenario, categories=orden, ordered=True)
df = df.sort_values("escenario")

def graf(col, titulo, archivo):
    ax = df.plot(kind="bar", x="escenario", y=col, figsize=(7,4), legend=False)
    ax.set_title(titulo); ax.set_ylabel("Tiempo promedio (ms)")
    ax.set_xlabel("Escenario")
    for p in ax.patches:                       # mostrar valor encima de cada barra
        ax.text(p.get_x() + p.get_width()/2, p.get_height() + 0.02,
                f"{p.get_height():.3f}", ha="center", va="bottom", fontsize=8)
    plt.tight_layout(); plt.savefig(f"bench/{archivo}", dpi=300); plt.clf()

graf("sign_ms",      "Tiempo para FIRMAR (RSA-SHA256)",          "fig_firma.png")
graf("cifTabla_ms",  "Tiempo para CIFRAR la TABLA (AES-CBC)",    "fig_cif_tabla.png")
graf("verif_ms",     "Tiempo para VERIFICAR la consulta (HMAC)", "fig_verif.png")

# gráfico comparativo simétrico vs asimétrico
ax = df.plot(kind="bar", x="escenario",
             y=["cifRespSym_ms","cifRespAsim_ms"],
             figsize=(7,4))
ax.set_title("Cifrado de la RESPUESTA: Simétrico (AES) vs Asimétrico (RSA)")
ax.set_ylabel("Tiempo promedio (ms)"); ax.set_xlabel("Escenario")
ax.legend(["AES-CBC","RSA-1024"], loc="upper left")
plt.tight_layout(); plt.savefig("bench/fig_resp_sym_vs_asym.png", dpi=300)
plt.clf()

print("Gráficas guardadas en /bench")
