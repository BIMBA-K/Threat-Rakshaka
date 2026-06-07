/**
 * IP Geolocation Map Component
 * Completely separate module for mapping IP addresses.
 */

(function() {
    // 1. Setup UI Styles
    const style = document.createElement('style');
    style.textContent = `
        /* Map Modal Styles */
        #ip-map-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(2, 6, 23, 0.85);
            backdrop-filter: blur(8px);
            z-index: 10000;
            display: none;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.3s ease-out;
        }

        #ip-map-modal.active {
            display: flex;
        }

        .map-modal-content {
            width: 90%;
            max-width: 800px;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            overflow: hidden;
            position: relative;
        }

        .map-modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .map-modal-header h2 {
            margin: 0;
            font-size: 1.25rem;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .map-close-btn {
            background: rgba(255, 255, 255, 0.05);
            border: none;
            color: #94a3b8;
            width: 32px;
            height: 32px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .map-close-btn:hover {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }

        #map-container {
            height: 450px;
            width: 100%;
            background: #020617;
        }

        /* Leaflet Overrides */
        .leaflet-container {
            font-family: 'Inter', sans-serif !important;
        }
        .leaflet-popup-content-wrapper {
            background: #0f172a !important;
            color: #fff !important;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px !important;
        }
        .leaflet-popup-tip {
            background: #0f172a !important;
        }

        /* Loading Indicator */
        #map-loader {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 23, 42, 0.9);
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 10;
            color: var(--accent-cyan);
        }

        #map-loader.active {
            display: flex;
        }

        /* IP Highlighter */
        .ip-clickable {
            cursor: pointer !important;
            color: var(--accent-cyan) !important;
            text-decoration: underline dotted !important;
            transition: all 0.2s;
        }
        .ip-clickable:hover {
            color: #fff !important;
            text-decoration: underline !important;
            background: rgba(34, 211, 238, 0.1);
            border-radius: 4px;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.98); }
            to { opacity: 1; transform: scale(1); }
        }
    `;
    document.head.appendChild(style);

    // 2. Create Modal HTML
    const modalHTML = `
        <div id="ip-map-modal">
            <div class="map-modal-content">
                <div id="map-loader">
                    <i class="fa-solid fa-spinner fa-spin fa-3x" style="margin-bottom: 1rem;"></i>
                    <p>Geolocating Infrastructure...</p>
                </div>
                <div class="map-modal-header">
                    <h2><i class="fa-solid fa-earth-americas"></i> IP Geolocation Map <span id="map-ip-title" style="font-family: 'JetBrains Mono'; font-size: 0.9rem; opacity: 0.6; margin-left: 0.5rem;"></span></h2>
                    <button class="map-close-btn" onclick="closeMapModal()">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                </div>
                <div id="map-container"></div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    let mapInstance = null;

    // 3. Core Functions
    window.showIPLocation = function(ip) {
        if (!ip || ip === '--') return;
        
        // Clean IP (remove counts if present, e.g., "1.1.1.1 (5)")
        const cleanIp = ip.split(' ')[0];
        
        const modal = document.getElementById('ip-map-modal');
        const loader = document.getElementById('map-loader');
        const title = document.getElementById('map-ip-title');
        
        modal.classList.add('active');
        loader.classList.add('active');
        title.textContent = `[${cleanIp}]`;

        fetch(`http://ip-api.com/json/${cleanIp}`)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'fail') {
                    throw new Error(data.message || 'Location unavailable');
                }
                openMap(data, cleanIp);
            })
            .catch(err => {
                console.error('IP-API Error:', err);
                alert(`Location unavailable for ${cleanIp}: ${err.message}`);
                closeMapModal();
            })
            .finally(() => {
                loader.classList.remove('active');
            });
    };

    window.openMap = function(data, ip) {
        const lat = data.lat;
        const lon = data.lon;

        // Cleanup previous instance
        if (mapInstance) {
            mapInstance.remove();
        }

        // Initialize Map
        mapInstance = L.map('map-container').setView([lat, lon], 5);

        // Professional Dark Mode Map Tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(mapInstance);

        // Custom Marker
        const marker = L.marker([lat, lon]).addTo(mapInstance);
        
        marker.bindPopup(`
            <div style="padding: 5px;">
                <b style="color: var(--accent-cyan); font-size: 1.1rem; display: block; margin-bottom: 5px;">${ip}</b>
                <div style="font-size: 0.9rem; line-height: 1.4;">
                    <i class="fa-solid fa-location-dot"></i> <b>${data.city}</b>, ${data.country}<br>
                    <i class="fa-solid fa-map"></i> ${data.lat.toFixed(4)}, ${data.lon.toFixed(4)}<br>
                    <i class="fa-solid fa-building"></i> ${data.isp || 'N/A'}
                </div>
            </div>
        `).openPopup();

        // Small delay to ensure container size is correct
        setTimeout(() => {
            mapInstance.invalidateSize();
        }, 100);
    };

    window.closeMapModal = function() {
        const modal = document.getElementById('ip-map-modal');
        modal.classList.remove('active');
        if (mapInstance) {
            mapInstance.remove();
            mapInstance = null;
        }
    };

    // 4. Automatic IP Detection & Click Handler Attachment
    function attachHandlers() {
        // Target 1: The Top IP stat card
        const topIpElem = document.getElementById('stat-top-ip');
        if (topIpElem && !topIpElem.classList.contains('ip-clickable')) {
            topIpElem.classList.add('ip-clickable');
            topIpElem.onclick = function() {
                showIPLocation(this.innerText);
            };
        }

        // Target 2: Elements in the intelligence inspector panel
        const inspector = document.getElementById('panel-content');
        if (inspector) {
            const fontMediums = inspector.querySelectorAll('.font-medium');
            fontMediums.forEach(el => {
                const text = el.innerText.trim();
                // Basic IP Regex
                if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(text) && !el.classList.contains('ip-clickable')) {
                    el.classList.add('ip-clickable');
                    el.onclick = function() {
                        showIPLocation(text);
                    };
                }
            });
        }
    }

    // Use MutationObserver to watch for dynamic updates
    const observer = new MutationObserver(() => {
        attachHandlers();
    });

    // Start observing when document is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            observer.observe(document.body, { childList: true, subtree: true });
            attachHandlers();
        });
    } else {
        observer.observe(document.body, { childList: true, subtree: true });
        attachHandlers();
    }

})();
