//! Audio I/O via cpal.
//!
//! Provides microphone capture and speaker playback using the system's
//! default audio devices. On Linux with PipeWire, cpal uses the ALSA
//! backend which routes through PipeWire transparently.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::sync::{Arc, Mutex};

/// Audio device information.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub input_sample_rate: Option<u32>,
    pub output_sample_rate: Option<u32>,
    pub host: String,
}

/// Get information about available audio devices.
pub fn device_info() -> DeviceInfo {
    let host = cpal::default_host();
    let host_name = format!("{:?}", host.id());

    let input = host.default_input_device();
    let output = host.default_output_device();

    let input_name = input.as_ref().and_then(|d| d.name().ok());
    let output_name = output.as_ref().and_then(|d| d.name().ok());

    let input_rate = input
        .as_ref()
        .and_then(|d| d.default_input_config().ok())
        .map(|c| c.sample_rate().0);
    let output_rate = output
        .as_ref()
        .and_then(|d| d.default_output_config().ok())
        .map(|c| c.sample_rate().0);

    DeviceInfo {
        input_device: input_name,
        output_device: output_name,
        input_sample_rate: input_rate,
        output_sample_rate: output_rate,
        host: host_name,
    }
}

/// Record audio from the default input device.
///
/// Records until either:
/// - `max_duration` is reached, or
/// - Voice activity stops (silence detected after speech)
///
/// Returns 16kHz mono f32 PCM samples.
pub async fn record(
    max_duration: std::time::Duration,
    vad_threshold: f32,
    silence_timeout: std::time::Duration,
) -> Result<Vec<f32>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Audio capture runs in a blocking thread since cpal callbacks
    // are real-time and can't be async.
    let handle = tokio::task::spawn_blocking(move || {
        record_blocking(max_duration, vad_threshold, silence_timeout, tx)
    });

    // Wait for either the recording to finish or an error
    match rx.await {
        Ok(result) => result,
        Err(_) => {
            // Channel closed — check if the task panicked
            match handle.await {
                Ok(Err(e)) => Err(e),
                Ok(Ok(())) => Err("Recording ended unexpectedly".to_string()),
                Err(e) => Err(format!("Recording task panicked: {e}")),
            }
        }
    }
}

fn record_blocking(
    max_duration: std::time::Duration,
    vad_threshold: f32,
    silence_timeout: std::time::Duration,
    result_tx: tokio::sync::oneshot::Sender<Result<Vec<f32>, String>>,
) -> Result<(), String> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or("No input device available")?;

    let config = device
        .default_input_config()
        .map_err(|e| format!("No input config: {e}"))?;

    let sample_rate = config.sample_rate().0;
    let channels = config.channels() as usize;

    let samples: Arc<Mutex<Vec<f32>>> = Arc::new(Mutex::new(Vec::new()));
    let samples_clone = samples.clone();
    let start = std::time::Instant::now();
    let speech_detected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let speech_detected_clone = speech_detected.clone();
    let last_speech = Arc::new(Mutex::new(std::time::Instant::now()));
    let last_speech_clone = last_speech.clone();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_clone = done.clone();

    // Pre-allocate a scratch buffer for mono conversion to avoid
    // per-callback heap allocation. Sized for the largest expected
    // callback frame (48kHz * 100ms = 4800 samples).
    let mut scratch = Vec::<f32>::with_capacity(4800);

    let stream = device
        .build_input_stream(
            &config.into(),
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                if done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }

                // Convert to mono by averaging channels, reusing
                // the scratch buffer to avoid per-frame allocation.
                let mono_len = data.len() / channels;
                scratch.clear();
                if scratch.capacity() < mono_len {
                    scratch.reserve(mono_len - scratch.capacity());
                }
                for frame in data.chunks(channels) {
                    scratch.push(frame.iter().sum::<f32>() / channels as f32);
                }

                // Simple energy-based VAD
                let energy: f32 = scratch.iter().map(|s| s * s).sum::<f32>() / scratch.len() as f32;
                let rms = energy.sqrt();

                if rms > vad_threshold {
                    speech_detected_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                    *last_speech_clone.lock().unwrap() = std::time::Instant::now();
                }

                samples_clone.lock().unwrap().extend_from_slice(&scratch);
            },
            |err| {
                tracing::error!("Audio input error: {err}");
            },
            None,
        )
        .map_err(|e| format!("Failed to build input stream: {e}"))?;

    stream
        .play()
        .map_err(|e| format!("Failed to start recording: {e}"))?;

    // Poll for completion
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));

        let elapsed = start.elapsed();
        if elapsed >= max_duration {
            break;
        }

        // If speech was detected, check for silence timeout
        if speech_detected.load(std::sync::atomic::Ordering::Relaxed) {
            let since_speech = last_speech.lock().unwrap().elapsed();
            if since_speech >= silence_timeout {
                break;
            }
        }
    }

    done.store(true, std::sync::atomic::Ordering::Relaxed);
    drop(stream);

    let recorded = samples.lock().unwrap().clone();

    // Resample to 16kHz if needed (simple linear interpolation)
    let resampled = if sample_rate != 16000 {
        resample(&recorded, sample_rate, 16000)
    } else {
        recorded
    };

    let _ = result_tx.send(Ok(resampled));
    Ok(())
}

/// Play audio samples on the default output device.
///
/// Takes f32 PCM samples at the given sample rate.
pub async fn play(samples: Vec<f32>, sample_rate: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || play_blocking(&samples, sample_rate))
        .await
        .map_err(|e| format!("Playback task panicked: {e}"))?
}

fn play_blocking(samples: &[f32], sample_rate: u32) -> Result<(), String> {
    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or("No output device available")?;

    let config = device
        .default_output_config()
        .map_err(|e| format!("No output config: {e}"))?;

    let device_rate = config.sample_rate().0;
    let channels = config.channels() as usize;

    // Resample to device rate if needed
    let resampled = if sample_rate != device_rate {
        resample(samples, sample_rate, device_rate)
    } else {
        samples.to_vec()
    };

    // Expand mono to device channel count
    let expanded: Vec<f32> = resampled
        .iter()
        .flat_map(|&s| std::iter::repeat_n(s, channels))
        .collect();

    let data = Arc::new(expanded);
    let pos = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let data_clone = data.clone();
    let pos_clone = pos.clone();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_clone = done.clone();

    let stream = device
        .build_output_stream(
            &config.into(),
            move |output: &mut [f32], _: &cpal::OutputCallbackInfo| {
                let current = pos_clone.load(std::sync::atomic::Ordering::Relaxed);
                let remaining = data_clone.len() - current;
                let to_write = output.len().min(remaining);

                output[..to_write].copy_from_slice(&data_clone[current..current + to_write]);

                // Fill rest with silence
                for sample in &mut output[to_write..] {
                    *sample = 0.0;
                }

                pos_clone.store(current + to_write, std::sync::atomic::Ordering::Relaxed);

                if current + to_write >= data_clone.len() {
                    done_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            },
            |err| {
                tracing::error!("Audio output error: {err}");
            },
            None,
        )
        .map_err(|e| format!("Failed to build output stream: {e}"))?;

    stream
        .play()
        .map_err(|e| format!("Failed to start playback: {e}"))?;

    // Wait for playback to finish
    while !done.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Small drain delay for the audio buffer
    std::thread::sleep(std::time::Duration::from_millis(50));

    Ok(())
}

/// Simple linear interpolation resampler.
///
/// Good enough for voice (not music). Converts between sample rates
/// without external dependencies.
pub(crate) fn resample(samples: &[f32], from_rate: u32, to_rate: u32) -> Vec<f32> {
    if from_rate == to_rate || samples.is_empty() {
        return samples.to_vec();
    }

    let ratio = from_rate as f64 / to_rate as f64;
    let output_len = (samples.len() as f64 / ratio) as usize;
    let mut output = Vec::with_capacity(output_len);

    for i in 0..output_len {
        let src_pos = i as f64 * ratio;
        let idx = src_pos as usize;
        let frac = (src_pos - idx as f64) as f32;

        let sample = if idx + 1 < samples.len() {
            samples[idx] * (1.0 - frac) + samples[idx + 1] * frac
        } else if idx < samples.len() {
            samples[idx]
        } else {
            0.0
        };

        output.push(sample);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_identity() {
        let samples = vec![1.0, 2.0, 3.0, 4.0];
        let result = resample(&samples, 16000, 16000);
        assert_eq!(result, samples);
    }

    #[test]
    fn resample_upsample() {
        let samples = vec![0.0, 1.0];
        let result = resample(&samples, 8000, 16000);
        assert_eq!(result.len(), 4);
        // First sample should be 0.0, last should approach 1.0
        assert!((result[0] - 0.0).abs() < 0.01);
    }

    #[test]
    fn resample_downsample() {
        let samples = vec![0.0, 0.25, 0.5, 0.75, 1.0, 0.75, 0.5, 0.25];
        let result = resample(&samples, 16000, 8000);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn resample_empty() {
        let result = resample(&[], 16000, 8000);
        assert!(result.is_empty());
    }

    #[test]
    fn device_info_returns_something() {
        // This test just verifies the function doesn't panic.
        // It may not find devices in CI/headless environments.
        let info = device_info();
        assert!(!info.host.is_empty());
    }
}
