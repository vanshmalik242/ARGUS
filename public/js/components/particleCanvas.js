/**
 * Interactive Particle Canvas Background
 * Renders a slow-moving network of nodes that react to mouse hover.
 */
const ParticleCanvas = {
    canvas: null,
    ctx: null,
    particles: [],
    numParticles: 80,
    connectionDistance: 150,
    mouse: { x: null, y: null, radius: 200 },
    animationId: null,

    init() {
        this.canvas = document.getElementById('hero-canvas');
        if (!this.canvas) return;
        
        this.ctx = this.canvas.getContext('2d');
        this.resize();
        
        window.addEventListener('resize', () => {
            this.resize();
            this.createParticles();
        });
        
        this.canvas.addEventListener('mousemove', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            this.mouse.x = e.clientX - rect.left;
            this.mouse.y = e.clientY - rect.top;
        });
        
        this.canvas.addEventListener('mouseleave', () => {
            this.mouse.x = null;
            this.mouse.y = null;
        });

        this.createParticles();
        this.animate();
    },

    resize() {
        // Match parent container size
        this.canvas.width = this.canvas.parentElement.clientWidth;
        this.canvas.height = this.canvas.parentElement.clientHeight;
    },

    createParticles() {
        this.particles = [];
        // Adjust particle count based on screen width
        const count = Math.min(this.numParticles, Math.floor(this.canvas.width / 15));
        
        for (let i = 0; i < count; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                vx: (Math.random() - 0.5) * 0.5, // Slow horizontal speed
                vy: (Math.random() - 0.5) * 0.5, // Slow vertical speed
                radius: Math.random() * 2 + 1,
                color: `rgba(0, 240, 255, ${Math.random() * 0.5 + 0.1})` // Cyan variations
            });
        }
    },

    draw() {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Draw connections first so nodes appear on top
        for (let a = 0; a < this.particles.length; a++) {
            for (let b = a + 1; b < this.particles.length; b++) {
                const dx = this.particles[a].x - this.particles[b].x;
                const dy = this.particles[a].y - this.particles[b].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < this.connectionDistance) {
                    const opacity = 1 - (dist / this.connectionDistance);
                    this.ctx.strokeStyle = `rgba(0, 240, 255, ${opacity * 0.2})`;
                    this.ctx.lineWidth = 1;
                    this.ctx.beginPath();
                    this.ctx.moveTo(this.particles[a].x, this.particles[a].y);
                    this.ctx.lineTo(this.particles[b].x, this.particles[b].y);
                    this.ctx.stroke();
                }
            }
        }

        // Draw and update particles
        for (let p of this.particles) {
            p.x += p.vx;
            p.y += p.vy;

            // Bounce off edges
            if (p.x < 0 || p.x > this.canvas.width) p.vx *= -1;
            if (p.y < 0 || p.y > this.canvas.height) p.vy *= -1;
            
            // Mouse interaction radius push
            if (this.mouse.x != null) {
                const dx = p.x - this.mouse.x;
                const dy = p.y - this.mouse.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < this.mouse.radius) {
                    // Normalize and push away slightly
                    const force = (this.mouse.radius - dist) / this.mouse.radius;
                    p.x += (dx / dist) * force * 1.5;
                    p.y += (dy / dist) * force * 1.5;
                }
            }

            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            this.ctx.fillStyle = p.color;
            this.ctx.fill();
            
            // Subtle glow
            this.ctx.shadowBlur = 10;
            this.ctx.shadowColor = 'rgba(0, 240, 255, 0.8)';
            this.ctx.fill();
            this.ctx.shadowBlur = 0; // Reset
        }
    },

    animate() {
        this.draw();
        this.animationId = requestAnimationFrame(this.animate.bind(this));
    }
};
