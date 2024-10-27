d1<-scan("throughput-hmac.txt")
d2<-scan("throughput-no-hmac.txt")

pdf("throughput.pdf");
par(mfrow=c(2,1))
hist(d1, col="dark red", breaks=5, main="End-to-end throughput with hop-by-hop SHA256 authentication", xlab="Iperf throughput, Mbits/s")
grid(lwd=1, col="black", lty=1)
hist(d2, col="dark blue", breaks=5, main="End-to-end throughput without hop-by-hop authentication", xlab="Iperf throughput, Mbits/s")
grid(lwd=1, col="black", lty=1)
dev.off()
