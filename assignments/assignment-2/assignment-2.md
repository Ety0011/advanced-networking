<div style="display: flex; justify-content: space-between;">
  <span>Etienne Orio</span>
  <span>Advanced Networking</span>
  <span>2026</span>
</div>

# Assignment 2: Queuing Theory

## Exercise 1: Maximum Rate Possible

The total arrival rate $\lambda_i$ for each server is calculated by summing external arrivals and internal routing:

$$
\begin{align*}
    \lambda_1 &= r_1 + p_{31} \lambda_3 \\
    \lambda_2 &= r_2 + p_{12} \lambda_1 \\
    \lambda_3 &= r_3 + p_{13} \lambda_1 + p_{23} \lambda_2 \\
\end{align*}
$$

Substituting known values we get:

$$
\begin{align*}
    \lambda_1 &= r_1 + \lambda_3 \\
    \lambda_2 &= 1 + 0.8 \lambda_1 \\
    \lambda_3 &= 1 + 0.2 \lambda_1 + 0.2 \lambda_2
\end{align*}
$$

We solve the system by expressing all rates in terms of $r_1$:

$$
\begin{align*}
    \lambda_1 &= r_1 + 1 + 0.2 \lambda_1 + 0.2 \lambda_2 \\
    \lambda_1 &= r_1 + 1 + 0.2 \lambda_1 + 0.2 (1 + 0.8\lambda_1) \\
    \lambda_1 &= r_1 + 1 + 0.2 \lambda_1 + 0.2 + 0.16 \lambda_1 \\
    \lambda_1 &= \frac{r_1 + 1.2}{0.64} \\
    \lambda_1 &= \frac{25}{16} r_1 + \frac{15}{8} \\
    \\
    \lambda_2 &= 1 + 0.8 \lambda_1 \\
    \lambda_2 &= 1 + 0.8 \left( \frac{25}{16} r_1 + \frac{15}{8} \right) \\
    \lambda_2 &= 1 + \frac{5}{4} r_1 + \frac{3}{2} \\
    \lambda_2 &= \frac{5}{4} r_1 + \frac{5}{2} \\
    \\
    \lambda_3 &= 1 + 0.2 \lambda_1 + 0.2\lambda_2 \\
    \lambda_3 &= 1 + 0.2 \left( \frac{25}{16} r_1 + \frac{15}{8} \right) + 0.2 \left( \frac{5}{4} r_1 + \frac{5}{2} \right) \\
    \lambda_3 &= 1 + \frac{5}{16} r_1 + \frac{3}{8} + \frac{1}{4} r_1 + \frac{1}{2} \\
    \lambda_3 &= \frac{9}{16} r_1 + \frac{15}{8} \\
\end{align*}
$$

A queue is stable if its total arrival rate is strictly less than its service rate, in particular if $\lambda_i < 10$.

$$
\begin{align*}
    \lambda_1 &< 10 \\
    \frac{25}{16} r_1 + \frac{15}{8} &< 10 \\
    25 r_1 + 30 &< 160 \\
    r_1 &< \frac{26}{5} = 5.2 \\
    \\
    \lambda_2 &< 10 \\
    \frac{5}{4} r_1 + \frac{5}{2} &< 10 \\
    5 r_1 + 10 &< 40 \\
    r_1 &< 6 \\
    \\
    \lambda_3 &< 10 \\
    \frac{9}{16} r_1 + \frac{15}{8} &< 10 \\
    9 r_1 + 30 &< 160 \\
    r_1 &< \frac{130}{9} \approx 14.4 \\
    \\
\end{align*}
$$

The system remains stable only when the conditions for all servers are met. The bottleneck is server 1 with constraint $r_1 < 5.2$

## Exercise 2: Little’s Theorem

### a

Using Little's Theorem, we calculate the average number of customers $(N)$ in a stable system, given:
- Arrival rate $(\lambda)$: $5 \text{ minutes per patient} = \frac{1}{5} \text{ patients per minute}$
- Waiting time $(T)$: $3 \text{ hours} = 180 \text{ minutes}$

$$
\begin{align*}
    N &= \lambda T \\
    N &= \frac{1}{5} \cdot 180 \\
    N &= 36 \text{ patients}
\end{align*}
$$

### b

If the process was deterministic we would need a room of size 36. But here we are dealing with a poisson process and without any further information there is no theoretical upper limit to how many people can arrive in a burst. The room would need infinite capacity to "always" accommodate arrivals.

## Exercise 3: M/M/1 Queue Length

$N_Q$ represents all the $n - 1$ customers in the queue, meaning all customers except the one currently being served. Therefore following the same steps from the queuing theory notes we get:

$$
\begin{align*}
    E[N_Q] &= \sum_{n=1}^{\infin} (n - 1) P_n \\
    &= \sum_{n=1}^{\infin} n P_n - \sum_{n=1}^{\infin} P_n \\
    &= \sum_{n=1}^{\infin} n \rho^n (1 - \rho) - \sum_{n=1}^{\infin} \rho^n (1 - \rho) \\
    &= (1 - \rho) \sum_{n=1}^{\infin} n \rho^n - (1 - \rho) \sum_{n=1}^{\infin} \rho^n \\
    &= (1 - \rho) \frac{\rho}{(1 - \rho)^2} - (1 - \rho) \frac{\rho}{1 - \rho} \\
    &= \frac{\rho}{1 - \rho} - \rho \\
    &= \frac{\rho}{1 - \rho} - \frac{\rho - \rho^2}{1 - \rho} \\
    &= \frac{\rho^2}{1 - \rho} \\
\end{align*}
$$

## Exercise 4: M/M/1 Queue

### a

The number of packets in the system $n$ includes the queue plus the packet being served, so $n = N_Q + 1$. We calculate the probabilities using $P_n = \rho^n(1 - \rho)$ with these parameters:

- Packet size: $250 \text{ bytes} = 2000 \text{ bits}$
- Arrival rate $(\lambda)$: $450 \text{ packets per second}$
- Service rate $(\mu)$: $\frac{1,000,000 \text{ bits per second}}{2000 \text{ bits}} = 500 \text{ packets per second}$
- Utilization $(\rho)$: $\frac{\lambda}{\mu} = \frac{450}{500} = 0.9$

$$
\begin{align*}
    P(N_Q = 1) &= P_2 \\
    &= \rho^2 (1 - \rho) \\
    &= 0.9^2 (1 - 0.9) \\
    &= 0.081 \\
    \\
    P(N_Q = 2) &= P_3 \\
    &= \rho^3 (1 - \rho) \\
    &= 0.9^3 (1 - 0.9) \\
    &\approx 0.073 \\
    \\
    P(N_Q = 10) &= P_{11} \\
    &= \rho^{11} (1 - \rho) \\
    &= 0.9^{11} (1 - 0.9) \\
    &\approx 0.031
\end{align*}
$$

### b

Mean number in the system:

$$
\begin{align*}
    E[N] &= \frac{\rho}{1 - \rho} \\
    &= \frac{0.9}{1 - 0.9} \\
    &= 9 \text{ packets}
\end{align*}
$$

Mean number in the queue:

$$
\begin{align*}
    E[N_Q] &= \frac{\rho^2}{1 - \rho} \\
    &= \frac{0.9^2}{1 - 0.9} \\
    &= 8.1 \text{ packets}
\end{align*}
$$

### c

Mean waiting time in the system:

$$
\begin{align*}
    T &= \frac{E[N]}{\lambda} \\
    &= \frac{9}{450} \\
    &= 0.02 \text{ seconds}
\end{align*}
$$

Mean waiting time in the queue:

$$
\begin{align*}
    T &= \frac{E[N_Q]}{\lambda} \\
    &= \frac{8.1}{450} \\
    &= 0.018 \text{ seconds}
\end{align*}
$$