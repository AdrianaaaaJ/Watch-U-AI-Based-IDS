(function () {
    'use strict';

    const palette = {
        grid: '#1c3038',
        text: '#60747c',
        teal: '#38bdf8',
        fill: 'rgba(56, 189, 248, 0.10)',
        severity: {
            Critical: '#ff4d64',
            High: '#ff8a4c',
            Medium: '#f0c84b',
            Low: '#43b9dd'
        }
    };

    function prepareCanvas(canvas) {
        const rect = canvas.getBoundingClientRect();
        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.max(1, Math.round(rect.width * ratio));
        canvas.height = Math.max(1, Math.round(rect.height * ratio));
        const context = canvas.getContext('2d');
        context.setTransform(ratio, 0, 0, ratio, 0, 0);
        return { context, width: rect.width, height: rect.height };
    }

    function roundedLine(context, points) {
        if (!points.length) return;
        context.moveTo(points[0].x, points[0].y);
        for (let index = 0; index < points.length - 1; index += 1) {
            const current = points[index];
            const next = points[index + 1];
            const middleX = (current.x + next.x) / 2;
            context.bezierCurveTo(middleX, current.y, middleX, next.y, next.x, next.y);
        }
    }

    function drawLineChart() {
        const canvas = document.querySelector('[data-line-chart]');
        const source = document.getElementById('trend-data');
        if (!canvas || !source) return;

        let rows;
        try { rows = JSON.parse(source.textContent); } catch (_) { return; }
        const { context, width, height } = prepareCanvas(canvas);
        const padding = { top: 18, right: 12, bottom: 31, left: 36 };
        const chartWidth = width - padding.left - padding.right;
        const chartHeight = height - padding.top - padding.bottom;
        const maximum = Math.max(4, ...rows.map(row => Number(row.value) || 0));
        const gridMax = Math.ceil(maximum / 4) * 4;

        context.clearRect(0, 0, width, height);
        context.font = '9px "Segoe UI", sans-serif';
        context.textAlign = 'right';
        context.textBaseline = 'middle';
        for (let tick = 0; tick <= 4; tick += 1) {
            const y = padding.top + (chartHeight / 4) * tick;
            context.strokeStyle = palette.grid;
            context.lineWidth = 1;
            context.beginPath();
            context.moveTo(padding.left, y + .5);
            context.lineTo(width - padding.right, y + .5);
            context.stroke();
            context.fillStyle = palette.text;
            context.fillText(String(Math.round(gridMax - (gridMax / 4) * tick)), padding.left - 9, y);
        }

        const points = rows.map((row, index) => ({
            x: padding.left + (rows.length === 1 ? chartWidth / 2 : (chartWidth / (rows.length - 1)) * index),
            y: padding.top + chartHeight - ((Number(row.value) || 0) / gridMax) * chartHeight,
            label: row.label
        }));

        context.beginPath();
        roundedLine(context, points);
        context.lineTo(points[points.length - 1].x, padding.top + chartHeight);
        context.lineTo(points[0].x, padding.top + chartHeight);
        context.closePath();
        const gradient = context.createLinearGradient(0, padding.top, 0, padding.top + chartHeight);
        gradient.addColorStop(0, 'rgba(56, 189, 248, .24)');
        gradient.addColorStop(1, 'rgba(56, 189, 248, 0)');
        context.fillStyle = gradient;
        context.fill();

        context.beginPath();
        roundedLine(context, points);
        context.strokeStyle = palette.teal;
        context.lineWidth = 2;
        context.shadowBlur = 8;
        context.shadowColor = 'rgba(56, 189, 248, .45)';
        context.stroke();
        context.shadowBlur = 0;

        context.textAlign = 'center';
        context.textBaseline = 'top';
        points.forEach(point => {
            context.beginPath();
            context.fillStyle = '#0d1920';
            context.strokeStyle = palette.teal;
            context.lineWidth = 1.5;
            context.arc(point.x, point.y, 3.2, 0, Math.PI * 2);
            context.fill();
            context.stroke();
            context.fillStyle = palette.text;
            context.fillText(point.label, point.x, padding.top + chartHeight + 11);
        });
    }

    function drawDonutChart() {
        const canvas = document.querySelector('[data-donut-chart]');
        const source = document.getElementById('severity-data');
        if (!canvas || !source) return;
        let values;
        try { values = JSON.parse(source.textContent); } catch (_) { return; }

        const { context, width, height } = prepareCanvas(canvas);
        const centerX = width / 2;
        const centerY = height / 2;
        const radius = Math.max(20, Math.min(width, height) / 2 - 10);
        const total = Math.max(1, Object.values(values).reduce((sum, value) => sum + Number(value || 0), 0));
        let angle = -Math.PI / 2;
        context.clearRect(0, 0, width, height);
        context.lineWidth = 17;
        context.lineCap = 'butt';

        ['Critical', 'High', 'Medium', 'Low'].forEach(severity => {
            const slice = (Number(values[severity] || 0) / total) * Math.PI * 2;
            if (slice <= 0) return;
            context.beginPath();
            context.strokeStyle = palette.severity[severity];
            context.arc(centerX, centerY, radius - 10, angle + .025, angle + slice - .025);
            context.stroke();
            angle += slice;
        });
    }

    const menuButton = document.querySelector('[data-menu-toggle]');
    const sidebar = document.getElementById('sidebar');
    if (menuButton && sidebar) {
        menuButton.addEventListener('click', () => {
            const open = sidebar.classList.toggle('open');
            menuButton.setAttribute('aria-expanded', String(open));
        });
        document.addEventListener('click', event => {
            if (window.innerWidth <= 980 && sidebar.classList.contains('open') && !sidebar.contains(event.target) && !menuButton.contains(event.target)) {
                sidebar.classList.remove('open');
                menuButton.setAttribute('aria-expanded', 'false');
            }
        });
    }

    document.querySelectorAll('[data-dismiss]').forEach(button => {
        button.addEventListener('click', () => button.closest('.flash')?.remove());
    });

    document.querySelectorAll('[data-auto-submit]').forEach(select => {
        select.addEventListener('change', () => select.form?.requestSubmit());
    });

    document.querySelectorAll('[data-copy-target]').forEach(button => {
        button.addEventListener('click', async () => {
            const target = document.getElementById(button.dataset.copyTarget);
            if (!target) return;
            const original = button.textContent;
            try {
                await navigator.clipboard.writeText(target.textContent.trim());
                button.textContent = 'Path copied';
            } catch (_) {
                button.textContent = 'Select and copy the path';
            }
            window.setTimeout(() => { button.textContent = original; }, 1800);
        });
    });

    let resizeTimer;
    function renderCharts() {
        drawLineChart();
        drawDonutChart();
    }
    renderCharts();
    window.addEventListener('resize', () => {
        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(renderCharts, 120);
    });
})();
