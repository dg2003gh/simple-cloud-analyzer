#🚀 Simple Cloud Analyzer (SCA)

🔍 O Simple Cloud Analyzer é uma CLI multi-cloud (inicialmente com suporte a AWS) voltada para facilitar a identificação de configurações inseguras e boas práticas de segurança em contas cloud. Ele realiza varreduras em recursos como:

- EC2 (portas abertas ao mundo)

- RDS (exposição pública, subnets públicas, SGs)

- IAM (chaves antigas, senhas antigas, permissões amplas)

- EBS (volumes sem criptografia)

- EKS, ECS, VPC e mais...

No final, ele gera um relatório, além de exibir uma tabela formatada no terminal — ideal para quem precisa de agilidade em auditorias ou automações.

🧠 Motivação: Tornar a análise de segurança cloud algo mais acessível, transparente e rápido. O foco é simplicidade, cobertura de risco real, e extensibilidade multi-cloud (GCP e Azure em breve).
