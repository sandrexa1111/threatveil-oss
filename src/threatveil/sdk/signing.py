"""Sign at the actual collector boundary; keep keys outside the agent's authority.

Each collector signs independently. Never load both production private keys in
the agent process. Ground truth must be read from the authoritative action sink.
"""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.contracts import Observation, digest


def sign_observation(observation, private_key: Ed25519PrivateKey, role="observer"):
    if role not in {"observer", "ground_truth"}:
        raise ValueError("Unknown collector role")
    obs = Observation.model_validate(observation)
    payload = obs.model_dump(mode="json", exclude={"attestations"})
    message = ("threatveil-observation-v1:" + role + ":" + digest(payload)).encode()
    signatures = {**obs.attestations, role: base64.b64encode(private_key.sign(message)).decode()}
    return obs.model_copy(update={"attestations": signatures})
